import React from 'react';
import { 
  Activity, 
  ArrowUpRight, 
  GitCompare, 
  LayoutDashboard, 
  LogOut, 
  Moon, 
  Network, 
  ShieldAlert, 
  Sparkles,
  Sun, 
  Upload, 
  WifiOff 
} from 'lucide-react';
import { BrandMark } from './BrandMark';

interface SidebarProps {
  activeScreen: string; 
  setActiveScreen: (screen: string) => void; 
  openUploadModal: () => void;
  openTrustModal: () => void; 
  currentScanId: string | null; 
  projectName: string;
  user: { name: string; role: string; airGapped: boolean }; 
  onLogout: () => void;
  theme: 'light' | 'dark'; 
  onToggleTheme: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ 
  activeScreen, 
  setActiveScreen, 
  openUploadModal, 
  openTrustModal, 
  currentScanId, 
  projectName, 
  user, 
  onLogout, 
  theme, 
  onToggleTheme 
}) => {
  const items = [
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'findings', label: 'Findings', icon: ShieldAlert },
    { id: 'graph', label: 'Architecture', icon: Network },
    { id: 'verification', label: 'Verification', icon: GitCompare },
    { id: 'playground', label: 'Playground', icon: Sparkles },
  ];

  return (
    <header className="workspace-header">
      <button className="brand-lockup" onClick={() => setActiveScreen('dashboard')} aria-label="Keynova home">
        <span className="brand-mark"><BrandMark size={21}/></span>
        <span><b>KEYNOVA</b><small>QUANTUM READINESS</small></span>
      </button>

      <div className="header-project">
        <span className="project-status-dot"/>
        <div>
          <small>WORKSPACE</small>
          <strong>{projectName || 'Payment Core'}</strong>
        </div>
        <ArrowUpRight size={14}/>
      </div>

      <nav className="workspace-nav" aria-label="Main navigation">
        {items.map(({ id, label, icon: Icon }) => (
          <button 
            key={id} 
            aria-label={label} 
            title={label} 
            className={activeScreen === id ? 'active' : ''} 
            onClick={() => setActiveScreen(id)}
          >
            <Icon size={16}/>
            <span>{label}</span>
          </button>
        ))}
      </nav>

      <div className="header-actions">
        <button 
          className="quiet-icon-button theme-toggle" 
          onClick={onToggleTheme} 
          title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`} 
          aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
        >
          {theme === 'light' ? <Moon size={16}/> : <Sun size={16}/>}
        </button>

        <button 
          className="quiet-icon-button" 
          onClick={openTrustModal} 
          title="Air-gap status"
        >
          <WifiOff size={16}/>
        </button>

        <button 
          className="scan-button" 
          onClick={openUploadModal}
        >
          <Upload size={15}/> New scan
        </button>

        <div className="profile-chip">
          <span className="profile-avatar">{user.name.slice(0, 1).toUpperCase()}</span>
          <span className="profile-name">{user.name}</span>
          <button onClick={onLogout} title="Sign out">
            <LogOut size={15}/>
          </button>
        </div>
      </div>

      <div className="header-scan-indicator">
        <Activity size={13}/>
        {currentScanId ? 'Scan connected' : 'No scan'}
      </div>
    </header>
  );
};
