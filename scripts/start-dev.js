const { spawn, execSync } = require('node:child_process');
const path = require('node:path');

const rootDir = path.resolve(__dirname, '..');
const portsToClear = [3000, 3005];

function run(command, extraEnv = {}) {
  const child = spawn(command, {
    cwd: rootDir,
    shell: true,
    stdio: 'inherit',
    env: { ...process.env, ...extraEnv },
  });

  return new Promise((resolve, reject) => {
    child.on('exit', (code, signal) => {
      if (signal) {
        reject(new Error(`Command terminated by signal: ${signal}`));
        return;
      }

      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Command exited with code ${code}`));
      }
    });

    child.on('error', reject);
  });
}

function clearPort(port) {
  try {
    const output = execSync(`netstat -ano | findstr :${port} | findstr LISTENING`, {
      cwd: rootDir,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: true,
    });

    const pids = [...new Set(
      output
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => line.trim().split(/\s+/).at(-1))
        .filter((pid) => /^\d+$/.test(pid))
    )];

    for (const pid of pids) {
      try {
        execSync(`taskkill /PID ${pid} /F /T`, {
          cwd: rootDir,
          stdio: 'inherit',
          shell: true,
        });
        console.log(`Cleared stale process on port ${port} (PID ${pid})`);
      } catch {
        // Ignore if process already exited.
      }
    }
  } catch {
    // No process listening on this port.
  }
}

(async () => {
  for (const port of portsToClear) {
    clearPort(port);
  }

  try {
    await run('docker compose up -d postgres');
  } catch (error) {
    console.warn('Docker is not available or PostgreSQL is already running. Continuing...');
  }

  console.log('Starting VulnShield API and web app in the current terminal...');

  const child = spawn('pnpm', ['--parallel', '--filter', '@vuln-shield/api', '--filter', '@vuln-shield/web', 'dev'], {
    cwd: rootDir,
    shell: true,
    stdio: 'inherit',
    env: process.env,
  });

  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }

    process.exit(code ?? 0);
  });

  child.on('error', (error) => {
    console.error(error);
    process.exit(1);
  });
})();
