import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  Sparkles, 
  Play, 
  Copy, 
  Check, 
  AlertTriangle, 
  Code2, 
  RefreshCw,
  Info
} from 'lucide-react';
import { runBenchmark } from '../lib/api';
import type { BenchmarkResult, RemediationResponse } from '../types';

async function callRemediationApi(finding: any): Promise<RemediationResponse> {
  const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api/v1';
  try {
    const res = await fetch(`${API_BASE}/remediation/remediate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(finding)
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // fallback if backend is offline
  }

  // Fallback template for offline/standalone UI demo
  const isRsa = finding.algorithm === 'RSA';
  const isEcc = finding.algorithm.includes('EC');
  return {
    finding_id: finding.id || 'demo-finding',
    provider: 'deterministic_fallback',
    algorithm: finding.algorithm,
    target_standard: isRsa ? 'FIPS 203 (ML-KEM-768)' : isEcc ? 'FIPS 204 (ML-DSA-65)' : 'RFC 9106 (Argon2id) / RFC 7914 (scrypt)',
    explanation: isRsa 
      ? 'This codebase uses 2048-bit RSA for public-key establishment. Under Shor’s algorithm, CRQC can factor 2048-bit integers in polynomial time. Migrate to NIST FIPS 203 ML-KEM-768.'
      : isEcc
      ? 'Elliptic curve signatures over SECP256R1 are vulnerable to discrete logarithm solving on quantum hardware. Migrate to NIST FIPS 204 ML-DSA-65.'
      : 'Password storage requires memory-hard Key Derivation Functions (Argon2id or scrypt) to resist offline GPU brute-force attacks.',
    proposed_diff: `--- ${finding.file_path}\n+++ ${finding.file_path}\n@@ -1,4 +1,4 @@\n- ${finding.code_snippet}\n+ # REMEDIATED with NIST PQC standard\n`,
    warnings: [
      'Advisory patch: Proposed diff is an automated engineering recommendation.',
      'Requires human cryptographic review, protocol testing, and validation prior to production deployment.'
    ],
    migration_effort: 'medium'
  };
}

export const PlaygroundScreen: React.FC = () => {
  // Benchmark State
  const [selectedAlg, setSelectedAlg] = useState('ML-KEM-768');
  const [iterations, setIterations] = useState(10);
  const [benchmarkResult, setBenchmarkResult] = useState<BenchmarkResult | null>(null);
  const [isBenchmarking, setIsBenchmarking] = useState(false);
  const [benchError, setBenchError] = useState<string | null>(null);

  // Remediation State
  const sampleFindings = [
    {
      id: 'sample-rsa-01',
      title: 'RSA-2048 Public Key Exchange',
      algorithm: 'RSA',
      file_path: 'backend/crypto_service.py',
      line_start: 9,
      code_snippet: 'self.private_key = legacy_rsa.generate_private_key(public_exponent=65537, key_size=2048)',
      usage: 'key_generation',
      severity: 'critical' as const,
      asset_type: 'source_code'
    },
    {
      id: 'sample-ecc-02',
      title: 'ECC SECP256R1 JWT Signing',
      algorithm: 'ECC-SECP256R1',
      file_path: 'backend/auth.py',
      line_start: 7,
      code_snippet: 'self.signing_key = ec.generate_private_key(ec.SECP256R1())',
      usage: 'token_signing',
      severity: 'high' as const,
      asset_type: 'source_code'
    },
    {
      id: 'sample-md5-03',
      title: 'MD5 Legacy Password Hashing',
      algorithm: 'MD5',
      file_path: 'backend/hasher.py',
      line_start: 9,
      code_snippet: 'return hashlib.md5(f"{salt}:{password}".encode()).hexdigest()',
      usage: 'password_hashing',
      severity: 'low' as const,
      asset_type: 'source_code'
    },
    {
      id: 'sample-manifest-04',
      title: 'Legacy Cryptographic Dependency',
      algorithm: 'DES/RSA/RC4',
      file_path: 'manifests/requirements.txt',
      line_start: 1,
      code_snippet: 'pycryptodome==3.10.1',
      usage: 'dependency',
      severity: 'low' as const,
      asset_type: 'manifest',
      library: 'pycryptodome'
    }
  ];

  const [selectedFinding, setSelectedFinding] = useState(sampleFindings[0]);
  const [remediation, setRemediation] = useState<RemediationResponse | null>(null);
  const [, setIsRemediating] = useState(false);
  const [remediateError, setRemediateError] = useState<string | null>(null);
  const [copiedDiff, setCopiedDiff] = useState(false);

  useEffect(() => {
    handleRunBenchmark('ML-KEM-768', 10);
    handleGenerateRemediation(sampleFindings[0]);
  }, []);

  const handleRunBenchmark = async (alg: string, iters: number) => {
    setIsBenchmarking(true);
    setBenchError(null);
    try {
      const res = await runBenchmark(alg, iters);
      setBenchmarkResult(res);
    } catch (err: any) {
      setBenchError(err.message || 'Benchmark failed to execute');
    } finally {
      setIsBenchmarking(false);
    }
  };

  const handleGenerateRemediation = async (finding: typeof sampleFindings[0]) => {
    setIsRemediating(true);
    setRemediateError(null);
    try {
      const res = await callRemediationApi({
        id: finding.id,
        algorithm: finding.algorithm,
        file_path: finding.file_path,
        line_start: finding.line_start,
        code_snippet: finding.code_snippet,
        usage: finding.usage,
        severity: finding.severity,
        asset_type: finding.asset_type,
        library: (finding as any).library
      });
      setRemediation(res);
    } catch (err: any) {
      setRemediateError(err.message || 'Remediation generation failed');
    } finally {
      setIsRemediating(false);
    }
  };

  const handleCopyDiff = (diffText: string) => {
    navigator.clipboard.writeText(diffText);
    setCopiedDiff(true);
    setTimeout(() => setCopiedDiff(false), 2000);
  };

  const algorithms = [
    { id: 'ML-KEM-768', name: 'ML-KEM-768', standard: 'NIST FIPS 203', type: 'KEM (Level 3)' },
    { id: 'ML-KEM-1024', name: 'ML-KEM-1024', standard: 'NIST FIPS 203', type: 'KEM (Level 5)' },
    { id: 'ML-DSA-65', name: 'ML-DSA-65', standard: 'NIST FIPS 204', type: 'Signature (Level 3)' },
    { id: 'RSA-2048', name: 'RSA-2048', standard: 'Legacy PKCS#1', type: 'Classical Baseline' },
    { id: 'ECDSA-P256', name: 'ECDSA-P256', standard: 'Legacy FIPS 186', type: 'Classical Baseline' }
  ];

  return (
    <div className="p-8 space-y-6 max-w-6xl mx-auto h-full flex flex-col">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-zinc-900 border border-zinc-800 p-5 rounded-xl shadow-lg">
        <div>
          <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
            <Sparkles className="w-3.5 h-3.5" />
            <span>AI Remediation & Quantum-Resilience Lab</span>
          </div>
          <h1 className="text-xl font-bold text-zinc-100 font-sans mt-1">
            PQC Playground & Automated Migration Engine
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Live cryptographic benchmarking for NIST standardized lattice primitives and automated unified diff generation.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: PQC Live Benchmarking Lab */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-zinc-900 border border-zinc-800 p-5 rounded-xl space-y-4 shadow-lg">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-400" />
                <h2 className="text-sm font-bold text-zinc-100 font-sans">
                  Live Cryptographic Benchmark
                </h2>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                Native C/Python
              </span>
            </div>

            {/* Algorithm Selector Buttons */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">
                Select Primitive
              </label>
              <div className="grid grid-cols-1 gap-1.5">
                {algorithms.map((alg) => {
                  const isSelected = selectedAlg === alg.id;
                  return (
                    <button
                      key={alg.id}
                      onClick={() => {
                        setSelectedAlg(alg.id);
                        handleRunBenchmark(alg.id, iterations);
                      }}
                      className={`px-3 py-2 rounded-lg text-left text-xs transition-all flex items-center justify-between border ${
                        isSelected
                          ? 'bg-zinc-800 border-zinc-600 text-zinc-100 shadow-sm'
                          : 'bg-zinc-950/60 border-zinc-800/80 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700'
                      }`}
                    >
                      <div>
                        <div className="font-bold font-mono">{alg.name}</div>
                        <div className="text-[10px] text-zinc-500">{alg.standard}</div>
                      </div>
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        alg.id.startsWith('ML')
                          ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/60'
                          : 'bg-zinc-900 text-zinc-400 border border-zinc-800'
                      }`}>
                        {alg.type}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Benchmark Controls */}
            <div className="flex items-center gap-3 pt-2">
              <div className="flex-1">
                <div className="flex justify-between text-[11px] text-zinc-400 mb-1">
                  <span>Iterations</span>
                  <span className="font-mono text-zinc-200">{iterations}</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="50"
                  value={iterations}
                  onChange={(e) => setIterations(Number(e.target.value))}
                  className="w-full h-1.5 bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-emerald-500"
                />
              </div>

              <button
                onClick={() => handleRunBenchmark(selectedAlg, iterations)}
                disabled={isBenchmarking}
                className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-bold text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50 shrink-0 mt-3"
              >
                {isBenchmarking ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Measuring...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Benchmark</span>
                  </>
                )}
              </button>
            </div>

            {benchError && (
              <div className="p-3 rounded-lg bg-red-950/40 border border-red-900/50 text-red-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{benchError}</span>
              </div>
            )}

            {/* Benchmark Results Display */}
            {benchmarkResult && (
              <div className="pt-3 border-t border-zinc-800 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-400">NIST Standard:</span>
                  <span className="font-mono font-semibold text-zinc-200">{benchmarkResult.nist_standard}</span>
                </div>

                {/* Microsecond Latencies */}
                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="p-2.5 rounded-lg bg-zinc-950 border border-zinc-800">
                    <div className="text-[10px] text-zinc-500 uppercase font-medium">KeyGen</div>
                    <div className="text-sm font-bold font-mono text-emerald-400 mt-0.5">
                      {benchmarkResult.avg_keygen_latency_us} <span className="text-[10px] text-zinc-500 font-normal">µs</span>
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-zinc-950 border border-zinc-800">
                    <div className="text-[10px] text-zinc-500 uppercase font-medium">
                      {benchmarkResult.algorithm.includes('DSA') ? 'Sign' : 'Encap'}
                    </div>
                    <div className="text-sm font-bold font-mono text-emerald-400 mt-0.5">
                      {benchmarkResult.avg_encap_latency_us} <span className="text-[10px] text-zinc-500 font-normal">µs</span>
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-zinc-950 border border-zinc-800">
                    <div className="text-[10px] text-zinc-500 uppercase font-medium">
                      {benchmarkResult.algorithm.includes('DSA') ? 'Verify' : 'Decap'}
                    </div>
                    <div className="text-sm font-bold font-mono text-emerald-400 mt-0.5">
                      {benchmarkResult.avg_decap_latency_us} <span className="text-[10px] text-zinc-500 font-normal">µs</span>
                    </div>
                  </div>
                </div>

                {/* Byte Footprints */}
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="p-2.5 rounded-lg bg-zinc-950 border border-zinc-800 flex items-center justify-between">
                    <span className="text-zinc-400">Public Key Size:</span>
                    <span className="font-mono font-semibold text-zinc-200">
                      {benchmarkResult.public_key_bytes} bytes
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-zinc-950 border border-zinc-800 flex items-center justify-between">
                    <span className="text-zinc-400">Payload Size:</span>
                    <span className="font-mono font-semibold text-zinc-200">
                      {benchmarkResult.ciphertext_bytes} bytes
                    </span>
                  </div>
                </div>

                <div className="p-2.5 rounded-lg bg-zinc-900/60 border border-zinc-800 text-[11px] text-zinc-400 flex items-center justify-between">
                  <span>NIST Security Strength Level:</span>
                  <span className="font-bold text-emerald-400 font-mono">
                    Category {benchmarkResult.security_level} (AES-{benchmarkResult.security_level === 5 ? '256' : benchmarkResult.security_level === 3 ? '192' : '128'} Equivalent)
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: AI Remediation & Unified Diff Engine */}
        <div className="lg:col-span-7 space-y-4">
          <div className="bg-zinc-900 border border-zinc-800 p-5 rounded-xl space-y-4 shadow-lg">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-emerald-400" />
                <h2 className="text-sm font-bold text-zinc-100 font-sans">
                  AI Cryptographic Remediation Engine
                </h2>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
                Ollama / Deterministic Dual-Core
              </span>
            </div>

            {/* Test Finding Presets */}
            <div>
              <label className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider block mb-1.5">
                Select Finding Vulnerability to Remediate
              </label>
              <div className="grid grid-cols-2 gap-2">
                {sampleFindings.map((finding) => {
                  const isSelected = selectedFinding.id === finding.id;
                  return (
                    <button
                      key={finding.id}
                      onClick={() => {
                        setSelectedFinding(finding);
                        handleGenerateRemediation(finding);
                      }}
                      className={`p-2.5 rounded-lg text-left text-xs transition-all border ${
                        isSelected
                          ? 'bg-zinc-800 border-zinc-600 text-zinc-100'
                          : 'bg-zinc-950/60 border-zinc-800/80 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700'
                      }`}
                    >
                      <div className="font-bold truncate">{finding.title}</div>
                      <div className="text-[10px] text-zinc-500 font-mono truncate mt-0.5">
                        {finding.file_path}:{finding.line_start}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Current Finding Snippet */}
            <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 space-y-1.5">
              <div className="flex items-center justify-between text-[11px] text-zinc-400 font-mono">
                <span>Vulnerable AST Invocations: {selectedFinding.file_path}</span>
                <span className="uppercase text-red-400 font-semibold">{selectedFinding.severity}</span>
              </div>
              <pre className="font-mono text-xs text-red-300/90 overflow-x-auto p-2 rounded bg-zinc-900/80 border border-zinc-800/80">
                <code>{selectedFinding.code_snippet}</code>
              </pre>
            </div>

            {remediateError && (
              <div className="p-3 rounded-lg bg-red-950/40 border border-red-900/50 text-red-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{remediateError}</span>
              </div>
            )}

            {/* Remediation Result */}
            {remediation && (
              <div className="space-y-3 pt-2">
                {/* Meta Badges */}
                <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-lg bg-zinc-950 border border-zinc-800 text-xs">
                  <div>
                    <span className="text-zinc-400 mr-2">Target Standard:</span>
                    <span className="font-mono font-bold text-emerald-400">{remediation.target_standard}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-zinc-800 text-zinc-300">
                      Effort: {remediation.migration_effort}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-800 text-zinc-400">
                      {remediation.provider}
                    </span>
                  </div>
                </div>

                {/* Explanation */}
                <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 text-xs text-zinc-300 space-y-1">
                  <div className="text-[10px] font-semibold text-zinc-400 uppercase tracking-wider flex items-center gap-1">
                    <Info className="w-3 h-3 text-emerald-400" />
                    <span>Migration Guidance</span>
                  </div>
                  <p className="leading-relaxed">{remediation.explanation}</p>
                </div>

                {/* Unified Diff Viewer */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs text-zinc-400">
                    <span className="font-semibold text-zinc-300 flex items-center gap-1.5">
                      <Code2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Synthesized Unified Diff</span>
                    </span>
                    <button
                      onClick={() => handleCopyDiff(remediation.proposed_diff)}
                      className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs flex items-center gap-1 transition-colors"
                    >
                      {copiedDiff ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy Patch</span>
                        </>
                      )}
                    </button>
                  </div>

                  <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 font-mono text-xs overflow-x-auto max-h-64 leading-relaxed">
                    {remediation.proposed_diff.split('\n').map((line, idx) => {
                      let colorClass = 'text-zinc-300';
                      let bgClass = '';
                      if (line.startsWith('+') && !line.startsWith('+++')) {
                        colorClass = 'text-emerald-400 font-semibold';
                        bgClass = 'bg-emerald-950/30 -mx-3 px-3 block';
                      } else if (line.startsWith('-') && !line.startsWith('---')) {
                        colorClass = 'text-red-400 font-semibold line-through';
                        bgClass = 'bg-red-950/30 -mx-3 px-3 block';
                      } else if (line.startsWith('@@')) {
                        colorClass = 'text-blue-400';
                      } else if (line.startsWith('---') || line.startsWith('+++')) {
                        colorClass = 'text-zinc-500 font-bold';
                      }
                      return (
                        <div key={idx} className={`${colorClass} ${bgClass}`}>
                          {line || '\u00A0'}
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Cryptographic Warnings */}
                {remediation.warnings && remediation.warnings.length > 0 && (
                  <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-900/50 space-y-1.5">
                    <div className="text-[10px] font-semibold text-amber-400 uppercase tracking-wider flex items-center gap-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>Cryptographic Warnings & Required Human Review</span>
                    </div>
                    <ul className="text-xs text-amber-200/90 space-y-1 list-disc list-inside">
                      {remediation.warnings.map((w, i) => (
                        <li key={i} className="leading-snug">{w}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
