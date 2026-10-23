import { useState } from 'react';
import { Activity, Beaker, ChevronLeft, ChevronRight, GitCompareArrows, LayoutDashboard, Network, ShieldAlert, ShieldCheck } from 'lucide-react';

export type WorkspaceSection = 'dashboard' | 'findings' | 'graph' | 'verification' | 'playground';
interface SidebarProps { activeSection: WorkspaceSection; onNavigate: (section: WorkspaceSection) => void; }
const navigation: Array<{ id: WorkspaceSection; label: string; icon: typeof LayoutDashboard }> = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings Explorer', icon: ShieldAlert },
  { id: 'graph', label: 'Cryptographic Graph', icon: Network },
  { id: 'verification', label: 'Verification', icon: GitCompareArrows },
  { id: 'playground', label: 'PQC Playground', icon: Beaker },
];
export function Sidebar({ activeSection, onNavigate }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);
  return <aside className={`sidebar${collapsed ? ' collapsed' : ''}`}>
    <div className="sidebar-brand"><span className="brand-icon"><Activity size={18} /></span>{!collapsed && <span><strong>KEYNOVA</strong><small>QUANTUM READINESS</small></span>}</div>
    <div className="sidebar-label">{!collapsed && 'WORKSPACE'}</div>
    <nav aria-label="Workspace navigation">{navigation.map(({ id, label, icon: Icon }) => <button key={id} type="button" className={`nav-item${activeSection === id ? ' active' : ''}`} onClick={() => onNavigate(id)} title={collapsed ? label : undefined} aria-current={activeSection === id ? 'page' : undefined}><Icon size={17} strokeWidth={1.8} />{!collapsed && <span>{label}</span>}</button>)}</nav>
    <div className="sidebar-bottom"><div className="security-badge"><span className="security-icon"><ShieldCheck size={16} /></span>{!collapsed && <span><strong>Air-Gapped Analyst</strong><small>LOCAL PROCESSING ACTIVE</small></span>}</div><button type="button" className="collapse-button" onClick={() => setCollapsed(value => !value)} aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}>{collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}{!collapsed && 'Collapse'}</button></div>
  </aside>;
}
