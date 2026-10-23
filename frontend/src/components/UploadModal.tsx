import { useRef, useState } from 'react';
import { FileArchive, LoaderCircle, UploadCloud, X } from 'lucide-react';
import { uploadProjectArchive } from '../lib/api';

interface UploadModalProps { isOpen: boolean; onClose: () => void; projectId: string; onScanCompleted: (scanId: string) => void; }

export function UploadModal({ isOpen, onClose, projectId, onScanCompleted }: UploadModalProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  if (!isOpen) return null;

  const selectFile = (candidate?: File) => {
    if (!candidate) return;
    if (!candidate.name.toLowerCase().endsWith('.zip')) { setError('Choose a .zip archive to continue.'); return; }
    if (candidate.size > 25 * 1024 * 1024) { setError('The archive must be 25 MB or smaller.'); return; }
    setFile(candidate); setError('');
  };
  const startScan = async () => {
    if (!file) return;
    setBusy(true); setError('');
    try {
      const scan = await uploadProjectArchive(projectId, file);
      onScanCompleted(scan.id);
      setFile(null);
      onClose();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The archive could not be scanned.');
    } finally { setBusy(false); }
  };

  return <div className="modal-scrim" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose(); }}>
    <section className="scan-modal" role="dialog" aria-modal="true" aria-labelledby="upload-title">
      <header className="scan-modal-header"><div className="scan-modal-icon"><FileArchive size={18}/></div><div><span className="eyebrow">NEW ANALYSIS</span><h2 id="upload-title">Upload a codebase</h2><p>Choose a ZIP archive for local cryptographic analysis.</p></div><button className="scan-modal-close" onClick={onClose} disabled={busy} aria-label="Close upload dialog"><X size={17}/></button></header>
      <div className="scan-modal-body">
        <label className={`archive-dropzone${file ? ' has-file' : ''}`} onDragOver={event => event.preventDefault()} onDrop={event => { event.preventDefault(); selectFile(event.dataTransfer.files[0]); }}>
          <input ref={inputRef} type="file" accept=".zip,application/zip" onChange={event => selectFile(event.target.files?.[0])} disabled={busy}/>
          <span className="dropzone-icon"><UploadCloud size={21}/></span><b>{file ? file.name : 'Choose a ZIP archive'}</b><small>{file ? `${(file.size / 1048576).toFixed(1)} MB · Ready to scan` : 'or drag and drop it here · up to 25 MB'}</small>
        </label>
        {busy && <div className="upload-progress" role="status"><div><span className="progress-track"><i/></span><span>Uploading archive and starting scan…</span></div><LoaderCircle size={16} className="spinner"/></div>}
        {error && <p className="scan-modal-error" role="alert">{error}</p>}
      </div>
      <footer className="scan-modal-footer"><span><FileArchive size={14}/> ZIP archives only</span><div><button className="scan-modal-cancel" onClick={onClose} disabled={busy}>Cancel</button><button className="scan-modal-submit" onClick={startScan} disabled={!file || busy}>{busy ? 'Analyzing…' : 'Start scan'} <span>→</span></button></div></footer>
    </section>
  </div>;
}
