import { useState } from 'react';
import { Activity, ArrowUpRight } from 'lucide-react';
import { Sidebar, type WorkspaceSection } from './components/Sidebar';

const sectionCopy: Record<WorkspaceSection, { title: string; description: string }> = {
  dashboard: { title: 'Dashboard', description: 'A clear starting point for your cryptographic readiness work.' },
  findings: { title: 'Findings Explorer', description: 'Review cryptographic usage and prioritize what needs attention.' },
  graph: { title: 'Cryptographic Graph', description: 'Map relationships between source files, libraries, and algorithms.' },
  verification: { title: 'Verification', description: 'Compare scans and track migration progress.' },
  playground: { title: 'PQC Playground', description: 'Explore post-quantum algorithms and benchmarks.' },
};

export default function App() {
  const [section, setSection] = useState<WorkspaceSection>('dashboard');
  const active = sectionCopy[section];
  return (
    <div className="app-shell">
      <Sidebar activeSection={section} onNavigate={setSection} />
      <main className="workspace-main">
        <header className="topbar">
          <div className="breadcrumbs"><span>KEYNOVA</span><i>/</i><strong>{active.title}</strong></div>
          <div className="connection"><span className="live-dot" /> Local workspace <ArrowUpRight size={14} /></div>
        </header>
        <section className="welcome-panel">
          <div className="eyebrow"><Activity size={14} /> FRONTEND FOUNDATION</div>
          <h1>{active.title}</h1>
          <p>{active.description}</p>
          <div className="foundation-card">
            <span className="card-icon"><Activity size={18} /></span>
            <div><strong>Workspace scaffold is ready</strong><small>Navigation, design tokens, typed models, and API fallbacks are in place.</small></div>
            <span className="ready-badge"><i /> READY</span>
          </div>
        </section>
        <footer className="page-footer"><span>KEYNOVA <i /> POST-QUANTUM READINESS</span><span>Local-first by design</span></footer>
      </main>
    </div>
  );
}
