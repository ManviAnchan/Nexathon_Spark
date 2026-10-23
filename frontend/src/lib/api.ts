import type {
  Finding,
  GraphData,
  Project,
  Remediation,
  ScanComparison,
  ScanStatus,
  BenchmarkResult
} from '../types';

const API_BASE = (import.meta.env.VITE_API_URL as string | undefined) ||
  (typeof window !== 'undefined' && window.location.protocol === 'file:'
    ? 'http://127.0.0.1:8000/api/v1'
    : '/api/v1');

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (typeof body.detail === 'string') detail = body.detail;
    } catch {
      // Keep the HTTP status as the useful error when the response is not JSON.
    }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

export function fetchProjects(): Promise<Project[]> {
  return request<Project[]>('/projects');
}

export function createProject(name: string, repository_url?: string): Promise<Project> {
  return request<Project>('/projects', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, repository_url }),
  });
}

export function fetchProjectScans(projectId: string): Promise<ScanStatus[]> {
  return request<ScanStatus[]>(`/projects/${encodeURIComponent(projectId)}/scans`);
}

export function fetchScan(scanId: string): Promise<ScanStatus> {
  return request<ScanStatus>(`/scans/${encodeURIComponent(scanId)}`);
}

export function fetchFindings(scanId: string, severity?: string): Promise<{ scan_id: string; total: number; items: Finding[] }> {
  const query = severity ? `?severity=${encodeURIComponent(severity)}` : '';
  return request(`/scans/${encodeURIComponent(scanId)}/findings${query}`);
}

export function fetchScanDiff(scanId: string, baselineId: string): Promise<ScanComparison> {
  return request<ScanComparison>(
    `/scans/${encodeURIComponent(scanId)}/diff/${encodeURIComponent(baselineId)}`,
  );
}

export function fetchCryptoGraph(scanId: string): Promise<GraphData> {
  return request<GraphData>(`/graph/${encodeURIComponent(scanId)}`);
}

export interface ScanDispatchResponse {
  project_id: string;
  scan_id: string;
  archive_name: string;
  readiness_score: number;
  status: string;
}

export function uploadArchive(
  projectId: string,
  file: File,
  baselineScanId?: string,
): Promise<ScanDispatchResponse> {
  const form = new FormData();
  form.append('file', file);
  const params = new URLSearchParams();
  if (baselineScanId) params.set('baseline_scan_id', baselineScanId);
  const query = params.size ? `?${params.toString()}` : '';
  return request<ScanDispatchResponse>(
    `/projects/${encodeURIComponent(projectId)}/upload${query}`,
    { method: 'POST', body: form },
  );
}

export function cloneGitRepo(
  projectId: string,
  repositoryUrl: string,
  branch?: string,
  baselineScanId?: string
): Promise<ScanDispatchResponse> {
  return request<ScanDispatchResponse>(`/projects/${encodeURIComponent(projectId)}/git-clone`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      repository_url: repositoryUrl,
      branch: branch || undefined,
      baseline_scan_id: baselineScanId || undefined
    })
  });
}

export interface RemediationData {
  finding_id: string;
  provider: string;
  algorithm: string;
  target_standard: string;
  explanation: string;
  proposed_diff: string;
  warnings: string[];
  migration_effort: string;
}

export function fetchRemediation(findingId: string): Promise<RemediationData> {
  return request<RemediationData>(`/remediation/${encodeURIComponent(findingId)}/suggest-fix`, {
    method: 'POST',
  });
}

export function remediateFinding(payload: {
  id?: string;
  algorithm: string;
  file_path?: string;
  line_start?: number;
  code_snippet?: string;
  usage?: string;
  severity?: string;
  asset_type?: string;
  library?: string;
}): Promise<Remediation> {
  return request<Remediation>('/findings/remediate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export function suggestFindingFix(findingId: string): Promise<Remediation> {
  return request<Remediation>(`/findings/${encodeURIComponent(findingId)}/suggest-fix`, {
    method: 'POST',
  });
}

export function getCbomExportUrl(scanId: string): string {
  return `${API_BASE}/export/${encodeURIComponent(scanId)}/cbom`;
}

export function getPdfExportUrl(scanId: string): string {
  return `${API_BASE}/export/${encodeURIComponent(scanId)}/pdf`;
}

export interface BenchmarkData {
  algorithm: string;
  nist_standard: string;
  iterations: number;
  avg_keygen_latency_us: number;
  avg_encap_latency_us: number;
  avg_decap_latency_us: number;
  public_key_bytes: number;
  ciphertext_bytes: number;
  security_level: number;
}

export function runCryptoBenchmark(algorithm: string = 'ML-KEM-768', iterations: number = 20): Promise<BenchmarkData & BenchmarkResult> {
  return request<BenchmarkData & BenchmarkResult>('/playground/benchmark', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ algorithm, iterations }),
  });
}

export interface TlsInspectionData {
  host: string;
  port: number;
  resolved_ip: string;
  is_safe: boolean;
  tls_version: string;
  cipher_suite: string;
  certificate_subject: string;
  certificate_issuer: string;
  key_size: number;
  quantum_safe: boolean;
  error?: string | null;
}

export function inspectTls(host: string, port = 443): Promise<TlsInspectionData> {
  return request<TlsInspectionData>('/tls/inspect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host, port }),
  });
}
