import React, { useState } from 'react';
import {
  Activity,
  GitCompare,
  LayoutDashboard,
  LogOut,
  Moon,
  Network,
  ShieldAlert,
  Sparkles,
  Sun,
  Upload,
  WifiOff,
} from 'lucide-react';
import { BrandMark } from './BrandMark';
import type { Project } from '../types';

interface SidebarProps {
  activeScreen: string;
  setActiveScreen: (screen: string) => void;
  openUploadModal: () => void;
  openTrustModal: () => void;
  currentScanId: string | null;
  projectName: string;
  projects?: Project[];
  activeProjectId?: string | null;
  onSelectProject?: (project: Project) => void;
  onCreateProject?: (name: string) => Promise<void>;
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
  const [showLogoutModal, setShowLogoutModal] = useState(false);

  const items = [
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'findings', label: 'Findings', icon: ShieldAlert },
    { id: 'graph', label: 'Architecture', icon: Network },
    { id: 'verification', label: 'Verification', icon: GitCompare },
    { id: 'playground', label: 'Playground', icon: Sparkles },
  ];

  return (
    <>
      <header className="workspace-header">
        <button className="brand-lockup" onClick={() => setActiveScreen('dashboard')} aria-label="Keynova home">
          <span className="brand-mark"><BrandMark size={21}/></span>
          <span><b>KEYNOVA</b><small>QUANTUM READINESS</small></span>
        </button>

        {/* Clean Static Workspace Indicator (Dropdown removed) */}
        <div className="header-project" title={`Current Workspace: ${projectName || 'Keynova Workspace'}`}>
          <span className={`project-status-dot ${currentScanId ? 'connected' : ''}`}/>
          <div>
            <small>WORKSPACE</small>
            <strong>{projectName || 'Keynova Workspace'}</strong>
          </div>
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
            <button
              type="button"
              onClick={() => setShowLogoutModal(true)}
              title="Sign out"
              aria-label="Sign out"
            >
              <LogOut size={15}/>
            </button>
          </div>
        </div>

        <div className="header-scan-indicator">
          <Activity size={13}/>
          {currentScanId ? 'Scan connected' : 'Awaiting upload'}
        </div>
      </header>

      {/* Logout Confirmation Popup Modal */}
      {showLogoutModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
          role="presentation"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowLogoutModal(false);
          }}
        >
          <div
            className="w-full max-w-sm rounded-2xl bg-white dark:bg-[#282722] border border-zinc-200 dark:border-[#3b3931] p-6 shadow-2xl space-y-4 text-zinc-900 dark:text-zinc-100"
            role="dialog"
            aria-modal="true"
            aria-labelledby="logout-dialog-title"
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400 flex items-center justify-center shrink-0">
                <LogOut size={20} />
              </div>
              <div>
                <h3 id="logout-dialog-title" className="text-sm font-bold text-zinc-900 dark:text-zinc-100 font-['Outfit']">
                  Confirm Sign Out
                </h3>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">Exit active analyst session</p>
              </div>
            </div>
            <p className="text-xs text-zinc-600 dark:text-zinc-300 leading-relaxed">
              Are you sure you want to sign out? Your current session readiness score will be reset.
            </p>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowLogoutModal(false)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-zinc-600 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-[#34332c] transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowLogoutModal(false);
                  onLogout();
                }}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-500 text-white shadow-sm transition-all"
              >
                Confirm Sign Out
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
