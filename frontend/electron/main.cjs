const { app, BrowserWindow, shell } = require('electron');
const path = require('path');
const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');

let mainWindow = null;
let backendProcess = null;
const BACKEND_PORT = 8000;
const BACKEND_HEALTH_URL = `http://127.0.0.1:${BACKEND_PORT}/health`;

const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;

function checkBackendHealth(timeoutMs = 1500) {
  return new Promise((resolve) => {
    const req = http.get(BACKEND_HEALTH_URL, { timeout: timeoutMs }, (res) => {
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitForBackend(maxAttempts = 30, intervalMs = 300) {
  for (let i = 0; i < maxAttempts; i++) {
    const healthy = await checkBackendHealth();
    if (healthy) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

function resolvePythonExecutable(workspaceRoot) {
  // Check virtual environment first
  const venvBin = process.platform === 'win32'
    ? path.join(workspaceRoot, '.venv', 'Scripts', 'python.exe')
    : path.join(workspaceRoot, '.venv', 'bin', 'python3');

  if (fs.existsSync(venvBin)) {
    return venvBin;
  }

  // Fallback to system python
  return process.platform === 'win32' ? 'python' : 'python3';
}

async function startBackendIfNeeded() {
  const isAlreadyRunning = await checkBackendHealth(800);
  if (isAlreadyRunning) {
    console.log('[Desktop] Backend is already running on port', BACKEND_PORT);
    return;
  }

  const workspaceRoot = path.resolve(__dirname, '../../');
  const pythonPath = resolvePythonExecutable(workspaceRoot);
  console.log(`[Desktop] Starting Keynova Backend using: ${pythonPath}`);

  const env = {
    ...process.env,
    PYTHONPATH: path.join(workspaceRoot, 'backend'),
    PYTHONUNBUFFERED: '1',
  };

  backendProcess = spawn(
    pythonPath,
    ['-m', 'uvicorn', 'keynova.main:app', '--host', '127.0.0.1', '--port', String(BACKEND_PORT)],
    {
      cwd: workspaceRoot,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  );

  backendProcess.stdout.on('data', (data) => {
    console.log(`[Backend] ${data.toString().trim()}`);
  });

  backendProcess.stderr.on('data', (data) => {
    console.error(`[Backend ERR] ${data.toString().trim()}`);
  });

  backendProcess.on('exit', (code, signal) => {
    console.log(`[Backend] Process exited with code ${code}, signal ${signal}`);
  });

  const ready = await waitForBackend();
  if (!ready) {
    console.error('[Desktop] Backend failed to become healthy within timeout.');
  } else {
    console.log('[Desktop] Backend successfully initialized and healthy.');
  }
}

function stopBackend() {
  if (backendProcess && !backendProcess.killed) {
    console.log('[Desktop] Stopping backend process...');
    try {
      if (process.platform === 'win32') {
        spawn('taskkill', ['/pid', String(backendProcess.pid), '/T', '/F']);
      } else {
        backendProcess.kill('SIGTERM');
        setTimeout(() => {
          if (backendProcess && !backendProcess.killed) {
            backendProcess.kill('SIGKILL');
          }
        }, 2000);
      }
    } catch (e) {
      console.error('[Desktop] Error stopping backend:', e);
    }
  }
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#090d16',
    title: 'Keynova — Autonomous Post-Quantum Cryptographic Readiness Platform',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
    autoHideMenuBar: false,
  });

  // Open external links in default OS browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http:') || url.startsWith('https:')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  if (isDev) {
    const devUrl = 'http://127.0.0.1:5173';
    console.log(`[Desktop] Loading Dev URL: ${devUrl}`);
    mainWindow.loadURL(devUrl);
  } else {
    const prodFile = path.join(__dirname, '../dist/index.html');
    console.log(`[Desktop] Loading Production Bundle: ${prodFile}`);
    mainWindow.loadFile(prodFile);
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  await startBackendIfNeeded();
  await createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  stopBackend();
  app.quit();
});

app.on('before-quit', () => {
  stopBackend();
});

process.on('exit', () => {
  stopBackend();
});
