export interface Project {
  id: string;
  name: string;
  repository_url?: string;
  created_at: string;
}

export interface ScanStatus {
  id: string;
  project_id: string;
  status: 'pending' | 'analyzing' | 'completed' | 'failed';
  scan_type: string;
  archive_name?: string;
  total_files: number;
  scanned_files: number;
  coverage_percent: number;
  readiness_score: number;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    quantum_safe: number;
  };
  hndl_count: number;
  created_at: string;
  completed_at?: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  fingerprint: string;
  file_path: string;
  line_start: number;
  line_end: number;
  code_snippet: string;
  asset_type: string;
  algorithm: string;
  usage: string;
  library?: string;
  key_size?: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'quantum_safe';
  quantum_status: string;
  hndl: boolean;
  confidence: number;
  rule_id: string;
  evidence: string;
}

export interface Remediation {
  finding_id: string;
  provider: string;
  algorithm: string;
  target_standard: string;
  explanation: string;
  proposed_diff: string;
  warnings: string[];
  migration_effort: string;
}

export interface ScanComparison {
  id: string;
  baseline_scan_id: string;
  target_scan_id: string;
  readiness_delta: number;
  resolved_count: number;
  added_count: number;
  unchanged_count: number;
  resolved_findings: any[];
  added_findings: any[];
  verification_status: string;
  created_at: string;
}

export interface GraphData {
  scan_id: string;
  nodes: Array<{
    id: string;
    type: string;
    data: any;
    position: { x: number; y: number };
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    animated?: boolean;
  }>;
}

export interface BenchmarkResult {
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
