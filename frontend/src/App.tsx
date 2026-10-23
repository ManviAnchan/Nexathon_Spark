import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import { Dashboard } from './screens/Dashboard';
import { FindingsExplorer } from './screens/FindingsExplorer';
import { DependencyGraph } from './screens/DependencyGraph';
import { VerificationScreen } from './screens/VerificationScreen';
import { PlaygroundScreen } from './screens/PlaygroundScreen';
import { UploadModal } from './components/UploadModal';
import { LoginScreen } from './components/LoginScreen';
import { TrustAuditModal } from './components/TrustAuditModal';
import { Project, ScanStatus, Finding } from './types';
import { fetchProjects, createProject, fetchScan, fetchFindings, fetchProjectScans } from './lib/api';

export const App: React.FC = () => {
  const [theme, setTheme] = useState<'light' | 'dark'>(() =>
    localStorage.getItem('keynova_theme') === 'dark' ? 'dark' : 'light',
  );
  const [activeScreen, setActiveScreen] = useState('dashboard');
  const [projects, setProjects] = useState<Project[]>([]);
  const [activeProject, setActiveProject] = useState<Project | null>(null);
  const [currentScan, setCurrentScan] = useState<ScanStatus | null>(null);
  const [baselineScan, setBaselineScan] = useState<ScanStatus | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [showDemoData, setShowDemoData] = useState(false);

  // Sync theme with HTML document element so Tailwind dark: classes and CSS vars apply
  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      document.documentElement.setAttribute('data-theme', 'light');
    }
    localStorage.setItem('keynova_theme', theme);
  }, [theme]);

  const trackSurfacePointer = (event: React.PointerEvent<HTMLElement>) => {
    const surface = (event.target as HTMLElement).closest<HTMLElement>(
      '.dashboard-metric, .dashboard-panel, .enterprise-card',
    );
    if (!surface) return;
    const bounds = surface.getBoundingClientRect();
    surface.style.setProperty('--pointer-x', `${event.clientX - bounds.left}px`);
    surface.style.setProperty('--pointer-y', `${event.clientY - bounds.top}px`);
  };
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [isTrustOpen, setIsTrustOpen] = useState(false);

  // Authentication State
  const [user, setUser] = useState<{ name: string; role: string; airGapped: boolean } | null>(() => {
    const saved = localStorage.getItem('keynova_analyst');
    return saved ? JSON.parse(saved) : null;
  });

  const handleLogin = (newUser: { name: string; role: string; airGapped: boolean }) => {
    localStorage.setItem('keynova_analyst', JSON.stringify(newUser));
    setUser(newUser);
  };

  const handleLogout = () => {
    localStorage.removeItem('keynova_analyst');
    setUser(null);
  };

  const toggleTheme = () => {
    setTheme((current) => (current === 'light' ? 'dark' : 'light'));
  };

  useEffect(() => {
    if (!user) return;
    async function init() {
      try {
        let projs = await fetchProjects();
        if (projs.length === 0) {
          const newProj = await createProject('Quantum Vault Demo', 'https://github.com/keynova/quantum-vault.git');
          projs = [newProj];
        }
        setProjects(projs);
        const p = projs[0];
        setActiveProject(p);
        setShowDemoData(false);

        // Fetch existing scans from database
        const scans = await fetchProjectScans(p.id);
        if (scans.length > 0) {
          const latest = scans[0];
          setCurrentScan(latest);
          const fData = await fetchFindings(latest.id);
          setFindings(fData.items);
          if (scans.length > 1) {
            setBaselineScan(scans[scans.length - 1]);
          }
        }
      } catch (e) {
        console.error('Initialization error:', e);
        const demoProject: Project = {
          id: 'demo-payment-suite',
          name: 'sample-payment-suite',
          repository_url: '',
          created_at: new Date().toISOString(),
        };
        const demoScan: ScanStatus = {
          id: 'sample-vulnerable-scan',
          project_id: demoProject.id,
          status: 'completed',
          scan_type: 'archive',
          archive_name: demoProject.name,
          total_files: 12,
          scanned_files: 12,
          coverage_percent: 100,
          readiness_score: 46,
          severity_counts: { critical: 1, high: 2, medium: 1, low: 0, quantum_safe: 0 },
          hndl_count: 1,
          created_at: new Date().toISOString(),
        };
        const demoFindings: Finding[] = [
          { id: 'demo-1', scan_id: demoScan.id, fingerprint: 'rsa-keygen', file_path: 'src/crypto/rsa.py', line_start: 42, line_end: 42, code_snippet: 'RSA.generate(2048)', asset_type: 'key', algorithm: 'RSA-2048', usage: 'key_generation', library: 'pycryptodome', key_size: 2048, severity: 'critical', quantum_status: 'vulnerable', hndl: true, confidence: 0.99, rule_id: 'PQC-RSA-001', evidence: 'RSA key generation detected' },
          { id: 'demo-2', scan_id: demoScan.id, fingerprint: 'rsa-cipher', file_path: 'src/payments/encrypt.py', line_start: 18, line_end: 18, code_snippet: 'PKCS1_OAEP.new(key)', asset_type: 'cipher', algorithm: 'RSA-OAEP', usage: 'key_encapsulation', library: 'pycryptodome', severity: 'high', quantum_status: 'vulnerable', hndl: true, confidence: 0.93, rule_id: 'PQC-RSA-002', evidence: 'RSA encryption detected' },
          { id: 'demo-3', scan_id: demoScan.id, fingerprint: 'ecdh', file_path: 'src/auth/session.py', line_start: 76, line_end: 76, code_snippet: 'ec.generate_private_key()', asset_type: 'key', algorithm: 'ECDH P-256', usage: 'key_exchange', library: 'cryptography', key_size: 256, severity: 'high', quantum_status: 'vulnerable', hndl: false, confidence: 0.91, rule_id: 'PQC-ECC-001', evidence: 'Elliptic curve key exchange detected' },
          { id: 'demo-4', scan_id: demoScan.id, fingerprint: 'sha256', file_path: 'src/utils/signing.py', line_start: 21, line_end: 21, code_snippet: 'hashes.SHA256()', asset_type: 'hash', algorithm: 'SHA-256', usage: 'digest', library: 'cryptography', severity: 'medium', quantum_status: 'quantum_safe', hndl: false, confidence: 0.86, rule_id: 'PQC-HASH-001', evidence: 'Hash usage detected' },
        ];
        setProjects([demoProject]);
        setActiveProject(demoProject);
        setCurrentScan(demoScan);
        setFindings(demoFindings);
        setShowDemoData(true);
      }
    }
    init();
  }, [user]);

  const loadScanData = async (scanId: string) => {
    try {
      const scan = await fetchScan(scanId);
      if (!baselineScan && scan.readiness_score < 80) {
        setBaselineScan(scan);
      }
      setCurrentScan(scan);

      const fData = await fetchFindings(scanId);
      setFindings(fData.items);
    } catch (e) {
      console.error('Failed to load scan data:', e);
    }
  };

  if (!user) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return (
    <div className="app-shell flex flex-col h-screen w-screen overflow-hidden" data-theme={theme} onPointerMove={trackSurfacePointer}>
      {/* Topbar Navigation */}
      <Sidebar
        activeScreen={activeScreen}
        setActiveScreen={setActiveScreen}
        openUploadModal={() => setIsUploadOpen(true)}
        openTrustModal={() => setIsTrustOpen(true)}
        currentScanId={currentScan?.id || null}
        projectName={activeProject?.name || 'Quantum Vault Demo'}
        user={user}
        onLogout={handleLogout}
        theme={theme}
        onToggleTheme={toggleTheme}
      />

      {/* Main Content Area */}
      <main className="app-main flex-1 min-h-0 overflow-y-auto">
        {activeScreen === 'dashboard' && (
          <Dashboard
            scan={currentScan}
            findings={findings}
            isDemo={showDemoData}
            onOpenFinding={() => setActiveScreen('findings')}
            onNavigate={(screen) => screen === 'upload' ? setIsUploadOpen(true) : setActiveScreen(screen)}
          />
        )}

        {activeScreen === 'findings' && (
          <FindingsExplorer
            findings={findings}
          />
        )}

        {activeScreen === 'graph' && (
          <DependencyGraph
            scanId={currentScan?.id || null}
            projectName={activeProject?.name || 'Payment Gateway Core'}
          />
        )}

        {activeScreen === 'verification' && (
          <VerificationScreen
            currentScan={currentScan}
            baselineScan={baselineScan}
            onTriggerRescan={() => setIsUploadOpen(true)}
          />
        )}

        {activeScreen === 'playground' && (
          <PlaygroundScreen />
        )}
      </main>


      {/* Upload & Git Clone Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        projectId={activeProject?.id || ''}
        baselineScanId={baselineScan?.id || currentScan?.id || null}
        onScanCompleted={(newScanId) => {
          loadScanData(newScanId);
        }}
      />

      {/* Zero-Egress Air-Gapped Trust Verification Modal */}
      <TrustAuditModal
        isOpen={isTrustOpen}
        onClose={() => setIsTrustOpen(false)}
      />
    </div>
  );
};
