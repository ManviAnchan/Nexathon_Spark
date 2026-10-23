import React from 'react';
import {
  Activity,
  Check,
  ChevronDown,
  GitCompare,
  Globe2,
  LayoutDashboard,
  LogOut,
  Moon,
  Network,
  ShieldAlert,
  Sparkles,
  Sun,
  Upload,
  WifiOff,
  Plus,
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
  projects: Project[];
  activeProjectId: string | null;
  onSelectProject: (project: Project) => void;
  onCreateProject: (name: string) => Promise<void>;
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
  projects,
  activeProjectId,
  onSelectProject,
  onCreateProject,
  user,
  onLogout,
  theme,
  onToggleTheme
}) => {
  const [projectMenuOpen, setProjectMenuOpen] = React.useState(false);
  const [newProjectName, setNewProjectName] = React.useState('');
  const [isCreatingProject, setIsCreatingProject] = React.useState(false);
  const [projectError, setProjectError] = React.useState<string | null>(null);
  const projectSwitcherRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!projectMenuOpen) return;
    const closeOnOutsideClick = (event: MouseEvent) => {
      if (!projectSwitcherRef.current?.contains(event.target as Node)) setProjectMenuOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setProjectMenuOpen(false);
    };
    document.addEventListener('mousedown', closeOnOutsideClick);
    document.addEventListener('keydown', closeOnEscape);
    return () => {
      document.removeEventListener('mousedown', closeOnOutsideClick);
      document.removeEventListener('keydown', closeOnEscape);
    };
  }, [projectMenuOpen]);

  const items = [
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'findings', label: 'Findings', icon: ShieldAlert },
    { id: 'graph', label: 'Architecture', icon: Network },
    { id: 'verification', label: 'Verification', icon: GitCompare },
    { id: 'playground', label: 'Playground', icon: Sparkles },
    { id: 'tls', label: 'External TLS', icon: Globe2 },
  ];

  const createWorkspace = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const name = newProjectName.trim();
    if (!name) return;
    setIsCreatingProject(true);
    setProjectError(null);
    try {
      await onCreateProject(name);
      setNewProjectName('');
      setProjectMenuOpen(false);
    } catch (error) {
      setProjectError(error instanceof Error ? error.message : 'Project could not be created.');
    } finally {
      setIsCreatingProject(false);
    }
  };

  return (
    <header className="workspace-header">
      <button className="brand-lockup" onClick={() => { setProjectMenuOpen(false); setActiveScreen('dashboard'); }} aria-label="Keynova home">
        <span className="brand-mark"><BrandMark size={21}/></span>
        <span><b>KEYNOVA</b><small>QUANTUM READINESS</small></span>
      </button>

      <div className="project-switcher" ref={projectSwitcherRef}>
        <button
          type="button"
          className="header-project"
          aria-haspopup="dialog"
          aria-expanded={projectMenuOpen}
          aria-label={`Current workspace: ${projectName || 'Select workspace'}`}
          onClick={() => setProjectMenuOpen((open) => !open)}
        >
          <span className={`project-status-dot ${currentScanId ? 'connected' : ''}`}/>
          <span className="project-switcher-label">
            <small>WORKSPACE</small>
            <strong>{projectName || 'Select workspace'}</strong>
          </span>
          <ChevronDown className="project-switcher-chevron" size={13} aria-hidden="true" />
        </button>
        {projectMenuOpen ? (
          <div className="project-switcher-menu" role="dialog" aria-label="Switch or create project">
            <p className="project-menu-heading">Your projects</p>
            {projects.length ? (
              <div className="project-menu-list" role="listbox" aria-label="Projects">
                {projects.map((project) => (
                  <button
                    type="button"
                    role="option"
                    aria-selected={project.id === activeProjectId}
                    className="project-menu-option"
                    key={project.id}
                    onClick={() => {
                      onSelectProject(project);
                      setProjectMenuOpen(false);
                    }}
                  >
                    <span>{project.name}</span>
                    {project.id === activeProjectId ? <Check size={14} aria-hidden="true" /> : null}
                  </button>
                ))}
              </div>
            ) : (
              <p className="project-menu-empty">No projects yet. Create one to start scanning.</p>
            )}
            <form className="project-create-form" onSubmit={createWorkspace}>
              <label htmlFor="new-project-name">Create project</label>
              <div className="project-create-row">
                <input
                  id="new-project-name"
                  value={newProjectName}
                  onChange={(event) => setNewProjectName(event.target.value)}
                  placeholder="Project name"
                  maxLength={80}
                  required
                  disabled={isCreatingProject}
                />
                <button type="submit" aria-label="Create project" disabled={isCreatingProject || !newProjectName.trim()}>
                  <Plus size={15} aria-hidden="true" />
                </button>
              </div>
              {projectError ? <p className="project-menu-error" role="alert">{projectError}</p> : null}
            </form>
          </div>
        ) : null}
      </div>

      <nav className="workspace-nav" aria-label="Main navigation">
        {items.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            aria-label={label}
            title={label}
            className={activeScreen === id ? 'active' : ''}
            onClick={() => { setProjectMenuOpen(false); setActiveScreen(id); }}
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
          onClick={() => { setProjectMenuOpen(false); openUploadModal(); }}
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
        {currentScanId ? 'Scan connected' : 'Awaiting upload'}
      </div>
    </header>
  );
};
