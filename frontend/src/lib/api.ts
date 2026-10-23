/// <reference types="vite/client" />
import type { BenchmarkResult, Finding, GraphData, Project, ScanComparison, ScanStatus } from '../types';
export type { RemediationResponse } from '../types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api/v1';
const demoProject: Project = { id: 'demo-keynova', name: 'Keynova Demo Workspace', repository_url: '', created_at: new Date().toISOString() };
const demoScan: ScanStatus = { id: 'demo-scan', project_id: demoProject.id, status: 'completed', scan_type: 'archive', archive_name: 'demo-project.zip', total_files: 18, scanned_files: 18, coverage_percent: 100, readiness_score: 46, severity_counts: { critical: 1, high: 1, medium: 1, low: 1, quantum_safe: 0 }, hndl_count: 2, created_at: new Date().toISOString() };
const demoFindings: Finding[] = [
  { id: 'demo-rsa', scan_id: demoScan.id, fingerprint: 'demo-rsa', file_path: 'backend/crypto_service.py', line_start: 24, line_end: 24, code_snippet: 'rsa.generate_private_key(public_exponent=65537, key_size=2048)', asset_type: 'source_code', algorithm: 'RSA-2048', usage: 'key_generation', library: 'cryptography', key_size: 2048, severity: 'critical', quantum_status: 'quantum_vulnerable', hndl: true, confidence: 0.98, rule_id: 'PYTHON_RSA_KEYGEN', evidence: 'RSA key establishment may be vulnerable to future quantum attacks. Review where this key is used.' },
  { id: 'demo-ecc', scan_id: demoScan.id, fingerprint: 'demo-ecc', file_path: 'backend/auth.py', line_start: 41, line_end: 41, code_snippet: 'ec.generate_private_key(ec.SECP256R1())', asset_type: 'source_code', algorithm: 'ECC-SECP256R1', usage: 'token_signing', library: 'cryptography', key_size: 256, severity: 'high', quantum_status: 'quantum_vulnerable', hndl: true, confidence: 0.91, rule_id: 'PYTHON_ECC_SECP256R1', evidence: 'Elliptic-curve signatures may be vulnerable to future quantum attacks.' },
  { id: 'demo-md5', scan_id: demoScan.id, fingerprint: 'demo-md5', file_path: 'backend/hasher.py', line_start: 17, line_end: 17, code_snippet: 'hashlib.md5(password.encode()).hexdigest()', asset_type: 'source_code', algorithm: 'MD5', usage: 'password_hashing', library: 'hashlib', key_size: 128, severity: 'medium', quantum_status: 'classical_weakness', hndl: false, confidence: 0.99, rule_id: 'PYTHON_MD5_HASH', evidence: 'MD5 has known weaknesses and is not appropriate for password storage.' },
  { id: 'demo-dependency', scan_id: demoScan.id, fingerprint: 'demo-dependency', file_path: 'requirements.txt', line_start: 3, line_end: 3, code_snippet: 'pycryptodome==3.10.1', asset_type: 'manifest', algorithm: 'Legacy crypto dependency', usage: 'dependency', library: 'pycryptodome', severity: 'low', quantum_status: 'quantum_vulnerable', hndl: false, confidence: 0.9, rule_id: 'DEP_PYCRYPTODOME', evidence: 'Review whether this package is needed and whether the project can use a maintained, quantum-agile alternative.' },
];
async function request<T>(path: string, init?: RequestInit): Promise<T> { const response = await fetch(`${API_BASE}${path}`, init); if (!response.ok) throw new Error(`API request failed: ${response.status} ${response.statusText}`); return response.json() as Promise<T>; }
async function withFallback<T>(task: () => Promise<T>, fallback: T, allowDemoNotFound = false): Promise<T> { try { return await task(); } catch (error) { const isDemoNotFound = allowDemoNotFound && error instanceof Error && error.message.includes('API request failed: 404'); if (error instanceof TypeError || isDemoNotFound) return fallback; throw error; } }
export const fetchProjects = () => withFallback(() => request<Project[]>('/projects'), [demoProject]);
export const createProject = (name: string, repository_url?: string) => withFallback(() => request<Project>('/projects', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, repository_url }) }), { ...demoProject, id: `demo-${Date.now()}`, name });
export const uploadProjectArchive = (projectId: string, file: File) => { const body = new FormData(); body.append('file', file); return withFallback(() => request<ScanStatus>(`/projects/${encodeURIComponent(projectId)}/upload`, { method: 'POST', body }), { ...demoScan, id: `demo-${Date.now()}`, project_id: projectId, archive_name: file.name }, projectId.startsWith('demo-')); };
export const fetchScan = (scanId: string) => withFallback(() => request<ScanStatus>(`/scans/${encodeURIComponent(scanId)}`), { ...demoScan, id: scanId }, scanId.startsWith('demo-'));
export const fetchFindings = (scanId: string, severity?: string) => { const query = severity ? `?severity=${encodeURIComponent(severity)}` : ''; return withFallback(() => request<{ scan_id: string; total: number; items: Finding[] }>(`/scans/${encodeURIComponent(scanId)}/findings${query}`), { scan_id: scanId, total: demoFindings.length, items: demoFindings.map(finding => ({ ...finding, scan_id: scanId })) }, scanId.startsWith('demo-')); };
export const fetchScanDiff = (scanId: string, baselineId: string) => withFallback(() => request<ScanComparison>(`/scans/${encodeURIComponent(scanId)}/diff/${encodeURIComponent(baselineId)}`), { id: `demo-diff-${scanId}`, baseline_scan_id: baselineId, target_scan_id: scanId, readiness_delta: 0, resolved_count: 0, added_count: 0, unchanged_count: 0, verification_status: 'pending', resolved_findings: [], added_findings: [] }, scanId.startsWith('demo-') && baselineId.startsWith('demo-'));
export const fetchScanGraph = (scanId: string) => withFallback(() => request<GraphData>(`/graph/${encodeURIComponent(scanId)}`), { scan_id: scanId, nodes: [], edges: [] }, scanId.startsWith('demo-'));
export const runBenchmark = (algorithm = 'ML-KEM-768', iterations = 20) => withFallback(() => request<BenchmarkResult>('/playground/benchmark', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ algorithm, iterations }) }), { algorithm, nist_standard: algorithm.startsWith('ML-DSA') ? 'FIPS 204' : 'FIPS 203', iterations, avg_keygen_latency_us: 0, avg_encap_latency_us: 0, avg_decap_latency_us: 0, public_key_bytes: 0, ciphertext_bytes: 0, security_level: 3 });
export const inspectTls = (host: string, port = 443) => withFallback(() => request<{ host: string; port: number; resolved_ip: string; is_safe: boolean; tls_version: string; cipher_suite: string; certificate_subject: string; certificate_issuer: string; key_size: number; quantum_safe: boolean; error?: string | null }>('/tls/inspect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host, port }) }), { host, port, resolved_ip: '', is_safe: false, tls_version: 'Unavailable offline', cipher_suite: '', certificate_subject: '', certificate_issuer: '', key_size: 0, quantum_safe: false, error: 'Backend unavailable; showing offline fallback.' });

export async function downloadScanExport(scanId: string, format: 'cbom' | 'pdf'): Promise<void> {
  const response = await fetch(`${API_BASE}/export/${encodeURIComponent(scanId)}/${format}`);
  if (!response.ok) throw new Error(`Export failed: ${response.status} ${response.statusText}`);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `keynova-${scanId}.${format === 'cbom' ? 'json' : 'pdf'}`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export const suggestPqcMigration = (findingId: string) => request<import('../types').RemediationResponse>(`/findings/${encodeURIComponent(findingId)}/suggest-fix`, { method: 'POST' });
