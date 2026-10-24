import React, { useState } from 'react';
import { Activity, CheckCircle2, Globe2, Loader2, ShieldAlert, ShieldCheck } from 'lucide-react';
import { inspectTls, TlsInspectionData } from '../lib/api';

const resultRows: Array<{ label: string; field: keyof TlsInspectionData }> = [
  { label: 'Resolved address', field: 'resolved_ip' },
  { label: 'TLS version', field: 'tls_version' },
  { label: 'Negotiated cipher suite', field: 'cipher_suite' },
  { label: 'Certificate subject', field: 'certificate_subject' },
  { label: 'Certificate issuer', field: 'certificate_issuer' },
  { label: 'Cipher key size', field: 'key_size' },
];

export const ExternalTlsScreen: React.FC = () => {
  const [host, setHost] = useState('');
  const [port, setPort] = useState(443);
  const [result, setResult] = useState<TlsInspectionData | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);

  const runAudit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const targetHost = host.trim();
    if (!targetHost) return;
    setIsLoading(true);
    setRequestError(null);
    setResult(null);
    try {
      setResult(await inspectTls(targetHost, port));
    } catch (error) {
      setRequestError(error instanceof Error ? error.message : 'TLS inspection failed.');
    } finally {
      setIsLoading(false);
    }
  };

  const cardClass = 'rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm dark:border-zinc-800 dark:bg-zinc-900';

  return (
    <div className="external-tls-page p-6 md:p-8 space-y-5 max-w-7xl mx-auto">
      <header className={`${cardClass} flex flex-col gap-4 md:flex-row md:items-center md:justify-between`}>
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
            <Globe2 className="h-4 w-4" /> External TLS
          </div>
          <h1 className="mt-1 text-xl font-semibold text-zinc-900 dark:text-zinc-100">TLS endpoint inspector</h1>
          <p className="mt-1 max-w-2xl text-sm text-zinc-500 dark:text-zinc-400">
            Inspect a public domain’s negotiated TLS version, cipher suite, and certificate. Private or unsafe network targets are blocked by the scanner.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-zinc-500 dark:text-zinc-400">
          <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" /> SSRF-protected inspection
        </div>
      </header>

      <section className={cardClass}>
        <form className="grid grid-cols-1 gap-4 sm:grid-cols-[minmax(0,1fr)_120px_auto] sm:items-end" onSubmit={runAudit}>
          <label className="block text-xs font-medium text-zinc-600 dark:text-zinc-300">
            Domain
            <input
              className="mt-1.5 block w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-sm text-zinc-900 outline-none focus:border-zinc-400 focus:ring-2 focus:ring-zinc-200 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-800"
              value={host}
              onChange={(event) => setHost(event.target.value)}
              placeholder="Enter a public domain"
              autoComplete="url"
              spellCheck={false}
              required
              disabled={isLoading}
            />
          </label>
          <label className="block text-xs font-medium text-zinc-600 dark:text-zinc-300">
            Port
            <input
              className="mt-1.5 block w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2.5 text-sm text-zinc-900 outline-none focus:border-zinc-400 focus:ring-2 focus:ring-zinc-200 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-800"
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(event) => setPort(Number(event.target.value))}
              required
              disabled={isLoading}
            />
          </label>
          <button
            type="submit"
            disabled={isLoading || !host.trim() || port < 1 || port > 65535}
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg border border-[#d7d2c9] bg-[#e3dfd7] px-4 py-2 text-xs font-semibold text-[#514c43] shadow-sm transition-colors hover:bg-[#dad6ce] disabled:cursor-not-allowed disabled:opacity-50 dark:border-[#454239] dark:bg-[#35342d] dark:text-[#c9c2b4] dark:hover:bg-[#3d3b33]"
          >
            {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Activity className="h-4 w-4" />}
            {isLoading ? 'Inspecting…' : 'Audit endpoint'}
          </button>
        </form>
      </section>

      {requestError ? (
        <div role="alert" className={`${cardClass} flex items-start gap-3 text-sm text-red-700 dark:text-red-300`}>
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <div><strong className="font-semibold">The inspection request failed.</strong><p className="mt-1">{requestError}</p></div>
        </div>
      ) : null}

      {result ? (
        <section aria-live="polite" className={cardClass}>
          <div className="flex flex-col gap-3 border-b border-zinc-100 pb-4 dark:border-zinc-800 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Audit result</p>
              <h2 className="mt-1 text-lg font-semibold text-zinc-900 dark:text-zinc-100">{result.host}:{result.port}</h2>
            </div>
            <span className={`inline-flex w-fit items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-semibold ${result.is_safe ? 'bg-emerald-50 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300' : 'bg-amber-50 text-amber-800 dark:bg-amber-950/40 dark:text-amber-300'}`}>
              {result.is_safe ? <CheckCircle2 className="h-3.5 w-3.5" /> : <ShieldAlert className="h-3.5 w-3.5" />}
              {result.is_safe ? 'Verified connection' : 'Blocked or unverified'}
            </span>
          </div>

          {result.error ? (
            <p role="status" className="mt-4 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200">
              {result.error}
            </p>
          ) : null}

          <dl className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {resultRows.map(({ label, field }) => (
              <div key={field} className="min-w-0 rounded-xl bg-zinc-50 p-3 dark:bg-zinc-950/60">
                <dt className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">{label}</dt>
                <dd className="mt-1 break-words text-sm font-medium text-zinc-800 dark:text-zinc-200">
                  {field === 'key_size' ? `${result.key_size} bits` : result[field] || 'N/A'}
                </dd>
              </div>
            ))}
            <div className="min-w-0 rounded-xl bg-zinc-50 p-3 dark:bg-zinc-950/60">
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">PQC / hybrid cipher observed</dt>
              <dd className="mt-1 text-sm font-medium text-zinc-800 dark:text-zinc-200">{result.quantum_safe ? 'Yes' : 'No'}</dd>
            </div>
          </dl>
        </section>
      ) : null}
    </div>
  );
};
