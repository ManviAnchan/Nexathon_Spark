import React, { useState, useEffect, useRef } from 'react';
import { Sidebar } from './components/Sidebar';
import { Dashboard } from './screens/Dashboard';
import { FindingsExplorer } from './screens/FindingsExplorer';
import { DependencyGraph } from './screens/DependencyGraph';
import { VerificationScreen } from './screens/VerificationScreen';
import { PlaygroundScreen } from './screens/PlaygroundScreen';
import { UploadModal } from './components/UploadModal';
import { LoginScreen } from './components/LoginScreen';
import { TrustAuditModal } from './components/TrustAuditModal';
import { DisplayScaleControl } from './components/DisplayScaleControl';
import { ExternalTlsScreen } from './screens/ExternalTlsScreen';
import { Project, ScanStatus, Finding } from './types';
import { fetchProjects, createProject, fetchScan, fetchFindings, fetchProjectScans } from './lib/api';

export const App: React.FC = () => {
  const uploadedScanIdsKey = 'keynova_uploaded_scan_ids_v2';
  const activeProjectIdKey = 'keynova_active_project_id';
  const userProjectIdsKey = 'keynova_user_project_ids';
  const [theme, setTheme] = useState<'light' | 'dark'>(() =>
    localStorage.getItem('keynova_theme') === 'dark' ? 'dark' : 'light',
  );
  const [displayScale, setDisplayScale] = useState(() => {
    const saved = Number(localStorage.getItem('keynova_display_scale'));
    return Number.isFinite(saved) && saved >= 25 && saved <= 250 && saved % 5 === 0 ? saved : 100;
  });
  const [activeScreen, setActiveScreen] = useState('dashboard');
  const [projects, setProjects] = useState<Project[]>([]);
  const [activeProject, setActiveProject] = useState<Project | null>(null);
  const [currentScan, setCurrentScan] = useState<ScanStatus | null>(null);
  const [baselineScan, setBaselineScan] = useState<ScanStatus | null>(null);
  const [availableScans, setAvailableScans] = useState<ScanStatus[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [appError, setAppError] = useState<string | null>(null);
  const projectLoadRequest = useRef(0);

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
    const shell = event.currentTarget;
    const scale = displayScale / 100;
    shell.classList.add('cursor-active');
    shell.style.setProperty('--cursor-x', `${event.clientX / scale}px`);
    shell.style.setProperty('--cursor-y', `${event.clientY / scale}px`);
    const surface = (event.target as HTMLElement).closest<HTMLElement>(
      '.dashboard-metric, .dashboard-panel, .enterprise-card',
    );
    if (!surface) return;
    const bounds = surface.getBoundingClientRect();
    surface.style.setProperty('--pointer-x', `${(event.clientX - bounds.left) / scale}px`);
    surface.style.setProperty('--pointer-y', `${(event.clientY - bounds.top) / scale}px`);
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

  const selectProject = async (project: Project | null) => {
    const requestId = ++projectLoadRequest.current;
    setAppError(null);
    setActiveProject(project);
    setCurrentScan(null);
    setBaselineScan(null);
    setAvailableScans([]);
    setFindings([]);
    if (!project) {
      localStorage.removeItem(activeProjectIdKey);
      return;
    }

    localStorage.setItem(activeProjectIdKey, project.id);
    try {
      const uploadedScanIds = JSON.parse(localStorage.getItem(uploadedScanIdsKey) || '[]') as string[];
      const scans = (await fetchProjectScans(project.id)).filter((scan) => uploadedScanIds.includes(scan.id));
      if (requestId !== projectLoadRequest.current) return;
      setAvailableScans(scans);
      const latestScan = scans[0] || null;
      setCurrentScan(latestScan);
      setBaselineScan(scans[1] || null);
      if (!latestScan) return;
      const fData = await fetchFindings(latestScan.id);
      if (requestId === projectLoadRequest.current) setFindings(fData.items);
    } catch (error) {
      if (requestId === projectLoadRequest.current) {
        console.error('Failed to load project scans:', error);
        setAppError(error instanceof Error ? error.message : 'Could not load this workspace’s scans.');
      }
    }
  };

  const createWorkspace = async (name: string) => {
    const project = await createProject(name.trim());
    const userProjectIds = JSON.parse(localStorage.getItem(userProjectIdsKey) || '[]') as string[];
    if (!userProjectIds.includes(project.id)) {
      localStorage.setItem(userProjectIdsKey, JSON.stringify([...userProjectIds, project.id]));
    }
    setProjects((existing) => [project, ...existing.filter((item) => item.id !== project.id)]);
    await selectProject(project);
  };

  useEffect(() => {
    if (!user) return;
    async function init() {
      try {
        const projs = await fetchProjects();
        const uploadedScanIds = new Set(JSON.parse(localStorage.getItem(uploadedScanIdsKey) || '[]') as string[]);
        const userProjectIds = new Set(JSON.parse(localStorage.getItem(userProjectIdsKey) || '[]') as string[]);
        const eligibleProjects = await Promise.all(projs.map(async (project) => {
          if (userProjectIds.has(project.id)) return project;
          if (!uploadedScanIds.size) return null;
          try {
            const scans = await fetchProjectScans(project.id);
            return scans.some((scan) => uploadedScanIds.has(scan.id)) ? project : null;
          } catch {
            return null;
          }
        }));
        const visibleProjects = eligibleProjects.filter((project): project is Project => project !== null);
        setProjects(visibleProjects);
        const activeProjectId = localStorage.getItem(activeProjectIdKey);
        const project = visibleProjects.find((item) => item.id === activeProjectId) || visibleProjects[0] || null;
        await selectProject(project);
      } catch (e) {
        console.error('Initialization error:', e);
        setAppError(e instanceof Error ? e.message : 'Could not initialize the workspace.');
        setProjects([]);
        setActiveProject(null);
        setCurrentScan(null);
        setBaselineScan(null);
        setAvailableScans([]);
        setFindings([]);
      }
    }
    init();
  }, [user]);

  const loadScanData = async (scanId: string) => {
    const requestId = projectLoadRequest.current;
    setAppError(null);
    try {
      const scan = await fetchScan(scanId);
      if (requestId !== projectLoadRequest.current) return;
      setCurrentScan(scan);

      const fData = await fetchFindings(scanId);
      if (requestId !== projectLoadRequest.current) return;
      setFindings(fData.items);
      const uploadedScanIds = JSON.parse(localStorage.getItem(uploadedScanIdsKey) || '[]') as string[];
      const scans = (await fetchProjectScans(scan.project_id)).filter((item) => uploadedScanIds.includes(item.id));
      if (requestId === projectLoadRequest.current) setAvailableScans(scans);
    } catch (e) {
      console.error('Failed to load scan data:', e);
      if (requestId === projectLoadRequest.current) {
        setAppError(e instanceof Error ? e.message : 'The uploaded scan could not be loaded.');
      }
    }
  };

  const ensureProjectForUpload = async (archiveName: string) => {
    if (activeProject) return activeProject.id;
    const projectName = archiveName.replace(/\.zip$/i, '').replace(/[_-]+/g, ' ').trim();
    const project = await createProject(projectName || archiveName);
    const userProjectIds = JSON.parse(localStorage.getItem(userProjectIdsKey) || '[]') as string[];
    if (!userProjectIds.includes(project.id)) {
      localStorage.setItem(userProjectIdsKey, JSON.stringify([...userProjectIds, project.id]));
    }
    setProjects((existing) => [project, ...existing.filter((item) => item.id !== project.id)]);
    await selectProject(project);
    return project.id;
  };

  if (!user) {
    return (
      <>
        <div
          className="login-display-shell"
          style={{ '--app-scale': displayScale / 100 } as React.CSSProperties}
        >
          <LoginScreen onLogin={handleLogin} />
        </div>
        <DisplayScaleControl
          value={displayScale}
          theme={theme}
          onChange={(value) => {
            setDisplayScale(value);
            localStorage.setItem('keynova_display_scale', String(value));
          }}
        />
      </>
    );
  }

  return (
    <>
      <div
        className="app-shell flex flex-col h-screen w-screen overflow-hidden"
        data-theme={theme}
        style={{ '--app-scale': displayScale / 100 } as React.CSSProperties}
        onPointerMove={trackSurfacePointer}
        onPointerLeave={(event) => event.currentTarget.classList.remove('cursor-active')}
      >
      <div className="app-cursor-light" aria-hidden="true" />
      {/* Topbar Navigation */}
      <Sidebar
        activeScreen={activeScreen}
        setActiveScreen={setActiveScreen}
        openUploadModal={() => setIsUploadOpen(true)}
        openTrustModal={() => setIsTrustOpen(true)}
        currentScanId={currentScan?.id || null}
        projectName={activeProject?.name || currentScan?.archive_name || ''}
        projects={projects}
        activeProjectId={activeProject?.id || null}
        onSelectProject={(project) => { void selectProject(project); }}
        onCreateProject={createWorkspace}
        user={user}
        onLogout={handleLogout}
        theme={theme}
        onToggleTheme={toggleTheme}
      />

      {/* Main Content Area */}
      <main className="app-main flex-1 min-h-0 overflow-y-auto">
        {appError && (
          <div role="alert" className="mx-6 mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-300">
            <div className="flex items-start justify-between gap-3">
              <span>{appError}</span>
              <button type="button" className="text-xs underline" onClick={() => setAppError(null)}>Dismiss</button>
            </div>
          </div>
        )}
        {activeScreen === 'dashboard' && (
          <Dashboard
            scan={currentScan}
            findings={findings}
            onOpenFinding={() => setActiveScreen('findings')}
            onNavigate={(screen) => screen === 'upload' ? setIsUploadOpen(true) : setActiveScreen(screen)}
          />
        )}

        {activeScreen === 'findings' && (
          <FindingsExplorer
            findings={currentScan ? findings : []}
          />
        )}

        {activeScreen === 'graph' && (
          <DependencyGraph
            scanId={currentScan?.id || null}
            projectName={activeProject?.name || currentScan?.archive_name || ''}
          />
        )}

        {activeScreen === 'verification' && (
          <VerificationScreen
            currentScan={currentScan}
            baselineScan={baselineScan}
            availableScans={availableScans}
            onSelectBaseline={(scanId) => setBaselineScan(availableScans.find((scan) => scan.id === scanId) || null)}
            onTriggerRescan={() => setIsUploadOpen(true)}
          />
        )}

        {activeScreen === 'playground' && (
          <PlaygroundScreen findings={findings} enabled={Boolean(currentScan)} />
        )}
        {activeScreen === 'tls' && <ExternalTlsScreen />}
      </main>

      {/* Upload & Git Clone Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        projectId={activeProject?.id || ''}
        onEnsureProject={ensureProjectForUpload}
        baselineScanId={baselineScan?.id || currentScan?.id || null}
        onScanCompleted={(newScanId, comparedBaselineId) => {
          const uploadedScanIds = JSON.parse(localStorage.getItem(uploadedScanIdsKey) || '[]') as string[];
          if (!uploadedScanIds.includes(newScanId)) {
            localStorage.setItem(uploadedScanIdsKey, JSON.stringify([...uploadedScanIds, newScanId]));
          }
          setBaselineScan(comparedBaselineId
            ? availableScans.find((scan) => scan.id === comparedBaselineId) || null
            : null);
          loadScanData(newScanId);
        }}
      />

      {/* Zero-Egress Air-Gapped Trust Verification Modal */}
      <TrustAuditModal
        isOpen={isTrustOpen}
        onClose={() => setIsTrustOpen(false)}
      />
      </div>
      <DisplayScaleControl
        value={displayScale}
        theme={theme}
        onChange={(value) => {
          setDisplayScale(value);
          localStorage.setItem('keynova_display_scale', String(value));
        }}
      />
    </>
  );
};
