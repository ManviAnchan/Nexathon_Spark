import { useEffect, useState } from 'react';
import { Activity, ArrowUpRight } from 'lucide-react';
import { Sidebar, type WorkspaceSection } from './components/Sidebar';
import { Dashboard } from './screens/Dashboard';
import { FindingsExplorer } from './screens/FindingsExplorer';
import './findings.css';
import './dashboard.css';
import { UploadModal } from './components/UploadModal';
import { fetchFindings, fetchScan } from './lib/api';
import type { Finding, ScanStatus } from './types';

const sectionCopy: Record<WorkspaceSection, { title: string; description: string }> = {
  dashboard: { title: 'Dashboard', description: 'A clear view of your cryptographic readiness.' },
  findings: { title: 'Findings Explorer', description: 'Review cryptographic usage and prioritize what needs attention.' },
  graph: { title: 'Cryptographic Graph', description: 'Map relationships between source files, libraries, and algorithms.' },
  verification: { title: 'Verification', description: 'Compare scans and track migration progress.' },
  playground: { title: 'PQC Playground', description: 'Explore post-quantum algorithms and benchmarks.' },
};
const PROJECT_ID = 'demo-keynova';

export function App() {
  const [section, setSection] = useState<WorkspaceSection>('dashboard');
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [demoData, setDemoData] = useState(true);
  const active = sectionCopy[section];

  useEffect(() => {
    let cancelled = false;
    void Promise.all([fetchScan('demo-scan'), fetchFindings('demo-scan')]).then(([initialScan, result]) => {
      if (cancelled) return;
      setScan(initialScan);
      setFindings(result.items);
      setDemoData(initialScan.id.startsWith('demo-'));
    });
    return () => { cancelled = true; };
  }, []);

  const navigate = (destination: string) => {
    if (destination === 'upload') { setUploadOpen(true); return; }
    if (destination in sectionCopy) setSection(destination as WorkspaceSection);
  };

  const handleScanCompleted = async (scanId: string) => {
    const [nextScan, nextFindings] = await Promise.all([fetchScan(scanId), fetchFindings(scanId)]);
    setScan(nextScan);
    setFindings(nextFindings.items);
    setDemoData(nextScan.id.startsWith('demo-'));
    setSection('dashboard');
  };

  return (
    <div className="app-shell">
      <Sidebar activeSection={section} onNavigate={setSection} />
      <main className="workspace-main">
        <header className="topbar">
          <div className="breadcrumbs"><span>KEYNOVA</span><i>/</i><strong>{active.title}</strong></div>
          <div className="connection"><span className="live-dot" /> Local workspace <ArrowUpRight size={14} /></div>
        </header>
        {section === 'dashboard' ? (
          <Dashboard scan={scan} findings={findings} isDemo={demoData} onOpenFinding={finding => { setSelectedFinding(finding); setSection('findings'); }} onNavigate={navigate} />
        ) : section === 'findings' ? (
          <FindingsExplorer findings={findings} selectedFinding={selectedFinding} onSelectFinding={setSelectedFinding} onNavigate={navigate} />
        ) : (
          <section className="welcome-panel">
            <div className="eyebrow"><Activity size={14} /> FRONTEND FOUNDATION</div>
            <h1>{active.title}</h1><p>{active.description}</p>
            <div className="foundation-card"><span className="card-icon"><Activity size={18} /></span><div><strong>Screen foundation is ready</strong><small>This screen will be completed in its scheduled sprint milestone.</small></div></div>
          </section>
        )}
        <footer className="page-footer"><span>KEYNOVA <i /> POST-QUANTUM READINESS</span><span>Local-first by design</span></footer>
      </main>
      <UploadModal isOpen={uploadOpen} onClose={() => setUploadOpen(false)} projectId={PROJECT_ID} onScanCompleted={handleScanCompleted} />
    </div>
  );
}
