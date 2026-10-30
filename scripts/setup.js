#!/usr/bin/env node
/**
 * Guided setup: checks this machine, installs the small dependencies, and
 * ASKS before any large download (LLM models, MongoDB image). Skipping models
 * is fine — the built-in engine still answers commands, questions about the
 * service, and category tips.
 *
 *   npm run setup                # interactive
 *   npm run setup -- --yes       # accept every suggested download
 *   npm run setup -- --skip-models --no-input   # CI / non-interactive
 *
 * Uses only Node built-ins, so it runs before `npm install`.
 */

'use strict';

const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const readline = require('readline');

const ROOT = path.join(__dirname, '..');
const args = new Set(process.argv.slice(2));
const YES = args.has('--yes');
const NO_INPUT = args.has('--no-input') || !process.stdin.isTTY;
const SKIP_MODELS = args.has('--skip-models');

const OLLAMA_URL = (process.env.OLLAMA_URL || 'http://localhost:11434').replace(/\/$/, '');
const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost:27017';

// Approximate download size (GB) and comfortable RAM (GB) for common models.
const KNOWN = {
  'llama3.2:1b': [1.3, 4], 'llama3.2:3b': [2.0, 4], 'llama3.1:8b': [4.9, 8],
  'qwen2.5-coder:1.5b': [1.0, 4], 'qwen2.5-coder:3b': [1.9, 4], 'qwen2.5-coder:7b': [4.7, 8],
  'phi3:mini': [2.2, 4], 'mistral:7b': [4.1, 8], 'gemma2:2b': [1.6, 4],
};

// Models the server uses by default (overridable with the same env vars).
const MODELS = [
  { name: process.env.LLM_MODEL || 'llama3.2:3b', role: 'general answers (default)' },
  { name: process.env.LLM_MODEL_CODING || 'qwen2.5-coder:7b', role: 'coding questions' },
]
  .filter((m) => m.name.toLowerCase() !== 'none')
  .map((m) => ({ ...m, gb: (KNOWN[m.name] || [])[0] || null, ramGb: (KNOWN[m.name] || [])[1] || null }));

// --- output helpers ----------------------------------------------------------
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code) => (s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const bold = c('1'), dim = c('2'), green = c('32'), red = c('31'), amber = c('33'), teal = c('36');
const ok = (m) => console.log(`  ${green('✓')} ${m}`);
const bad = (m) => console.log(`  ${red('✗')} ${m}`);
const warn = (m) => console.log(`  ${amber('!')} ${m}`);
const info = (m) => console.log(`    ${dim(m)}`);
const step = (n, title) => console.log(`\n${teal(`[${n}]`)} ${bold(title)}`);

const status = { node: false, npm: false, python: false, mongo: false, ollama: false, models: [] };

function run(cmd, opts = {}) {
  try {
    return execSync(cmd, { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', ...opts }).trim();
  } catch {
    return null;
  }
}

async function ask(question, defaultYes = false) {
  if (YES) return true;
  if (NO_INPUT) return false;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const hint = defaultYes ? 'Y/n' : 'y/N';
  const answer = await new Promise((resolve) => rl.question(`    ${question} ${dim(`[${hint}]`)} `, resolve));
  rl.close();
  const a = answer.trim().toLowerCase();
  return a ? a.startsWith('y') : defaultYes;
}

function tcpReachable(host, port, timeout = 1500) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port, timeout }, () => { s.destroy(); resolve(true); });
    s.on('error', () => resolve(false));
    s.on('timeout', () => { s.destroy(); resolve(false); });
  });
}

function freeDiskGb(dir) {
  try {
    const st = fs.statfsSync(dir);
    return (st.bavail * st.bsize) / 1024 ** 3;
  } catch {
    return null;
  }
}

function gpuInfo() {
  const out = run('nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits');
  if (!out) return null;
  const [name, mem] = out.split('\n')[0].split(',').map((s) => s.trim());
  return { name, vramGb: Number(mem) / 1024 };
}

// --- steps -------------------------------------------------------------------
function checkNode() {
  step(1, 'Node.js');
  const [maj, min] = process.versions.node.split('.').map(Number);
  if (maj > 20 || (maj === 20 && min >= 19)) {
    ok(`Node ${process.versions.node}`);
    status.node = true;
  } else {
    bad(`Node ${process.versions.node} — version 20.19 or newer is required (https://nodejs.org)`);
  }
}

function installNodeDeps() {
  step(2, 'Server dependencies (npm)');
  const r = spawnSync('npm', ['install', '--no-audit', '--no-fund'], { cwd: ROOT, stdio: 'inherit', shell: process.platform === 'win32' });
  if (r.status === 0) {
    ok('npm packages installed');
    status.npm = true;
  } else {
    bad('npm install failed — see the output above');
  }
}

async function checkPython() {
  step(3, 'Python client (client.py, org_client.py)');
  const py = ['python3', 'python'].find((p) => run(`${p} --version`));
  if (!py) {
    warn('Python 3 not found — only needed for the command-line clients (https://python.org)');
    return;
  }
  ok(run(`${py} --version`));
  if (run(`${py} -c "import requests"`) !== null) {
    ok('requests is installed');
    status.python = true;
    return;
  }
  warn('The Python package "requests" is missing (small download, < 1 MB).');
  if (!(await ask('Install it now with pip (pip install -r requirements.txt)?', true))) {
    info('Skipped. Install later with: pip install -r requirements.txt');
    return;
  }
  const r = spawnSync(py, ['-m', 'pip', 'install', '--user', '-r', 'requirements.txt'], { cwd: ROOT, encoding: 'utf8' });
  if (r.status === 0) {
    ok('requests installed');
    status.python = true;
  } else if (/externally-managed/i.test(r.stderr || '')) {
    warn('This system manages Python packages itself. Use a virtual environment:');
    info(`${py} -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt`);
    info('or install the system package (e.g. sudo apt install python3-requests)');
  } else {
    bad('pip install failed:');
    info((r.stderr || '').trim().split('\n').slice(-3).join('\n    '));
  }
}

async function checkMongo() {
  step(4, 'MongoDB');
  const m = MONGO_URL.match(/^mongodb:\/\/(?:[^@/]*@)?([^:/,]+)(?::(\d+))?/);
  const host = m ? m[1] : 'localhost';
  const port = m && m[2] ? Number(m[2]) : 27017;
  if (await tcpReachable(host, port)) {
    ok(`MongoDB reachable at ${host}:${port}`);
    status.mongo = true;
    return;
  }
  bad(`MongoDB is not reachable at ${host}:${port}`);
  if (run('docker --version')) {
    warn('Docker is available. The official mongo:7 image is a ~700 MB download.');
    if (await ask('Start MongoDB in Docker now (docker run -d --name aap-mongo -p 27017:27017 mongo:7)?')) {
      const r = spawnSync('docker', ['run', '-d', '--name', 'aap-mongo', '-p', '27017:27017', 'mongo:7'], { stdio: 'inherit' });
      if (r.status === 0) await new Promise((res) => setTimeout(res, 3000)); // let mongod start
      if (r.status === 0 && (await tcpReachable(host, port))) {
        ok('MongoDB is running in Docker (container: aap-mongo)');
        status.mongo = true;
        return;
      }
      bad('Could not start MongoDB in Docker — see the output above');
    }
  }
  info('Install MongoDB Community: https://www.mongodb.com/try/download/community');
  info('or point the server at an existing database with MONGO_URL=mongodb://host:27017');
}

async function checkOllama() {
  step(5, 'Local LLM (optional)');
  const version = run('ollama --version');
  let reachable = false;
  try {
    reachable = (await fetch(`${OLLAMA_URL}/api/version`, { signal: AbortSignal.timeout(2000) })).ok;
  } catch {}
  if (!version && !reachable) {
    warn('Ollama is not installed. LLM answers are optional — the built-in engine works without it.');
    info('To enable LLM answers later: install Ollama from https://ollama.com/download, then run npm run setup again.');
    return null;
  }
  if (!reachable) {
    warn(`Ollama is installed (${version}) but not running at ${OLLAMA_URL}.`);
    info('Start it with: ollama serve   (or start the Ollama app), then run npm run setup again.');
    return null;
  }
  ok(`Ollama running at ${OLLAMA_URL}${version ? ` (${version.replace(/^ollama version is /i, 'v')})` : ''}`);
  status.ollama = true;
  const tags = await (await fetch(`${OLLAMA_URL}/api/tags`)).json();
  return new Set((tags.models || []).map((m) => m.name));
}

async function checkModels(installed) {
  step(6, 'LLM models');
  if (!installed) {
    info('Skipped — Ollama is not available.');
    return;
  }
  const ramGb = os.totalmem() / 1024 ** 3;
  const gpu = gpuInfo();
  const disk = freeDiskGb(process.env.OLLAMA_MODELS || os.homedir());
  info(`This machine: ${ramGb.toFixed(1)} GB RAM` +
    (gpu ? ` · ${gpu.name} (${gpu.vramGb.toFixed(1)} GB VRAM)` : ' · no NVIDIA GPU detected (CPU inference is slower)') +
    (disk !== null ? ` · ${disk.toFixed(1)} GB free disk` : ''));

  for (const model of MODELS) {
    if (installed.has(model.name)) {
      ok(`${model.name} — ${model.role} (already installed)`);
      status.models.push(model.name);
      continue;
    }
    warn(`${bold(model.name)} — ${model.role} — not installed (${model.gb ? `~${model.gb} GB download` : 'download size unknown'}).`);
    if (model.ramGb && ramGb < model.ramGb) info(`Needs about ${model.ramGb} GB RAM to run comfortably; this machine has ${ramGb.toFixed(1)} GB.`);
    if (disk !== null && model.gb && disk < model.gb + 1) {
      bad(`Not enough free disk space (${disk.toFixed(1)} GB) — skipping.`);
      continue;
    }
    if (SKIP_MODELS) {
      info('Skipped (--skip-models).');
      continue;
    }
    if (!(await ask(`Download ${model.name} now? This may take a while on slow connections.`))) {
      info(`Skipped. Download later with: ollama pull ${model.name}`);
      continue;
    }
    const r = spawnSync('ollama', ['pull', model.name], { stdio: 'inherit' });
    if (r.status === 0) {
      ok(`${model.name} downloaded`);
      status.models.push(model.name);
    } else {
      bad(`Download of ${model.name} failed — you can retry with: ollama pull ${model.name}`);
    }
  }
}

function summary() {
  console.log(`\n${bold('Summary')}`);
  const line = (flag, label, note) => console.log(`  ${flag ? green('✓') : amber('•')} ${label}${note ? dim(`  ${note}`) : ''}`);
  line(status.node && status.npm, 'Server', status.node && status.npm ? '' : 'fix the items above');
  line(status.mongo, 'MongoDB', status.mongo ? '' : 'required — start it before npm start');
  line(status.python, 'CLI clients', status.python ? '' : 'optional — pip install -r requirements.txt');
  if (status.models.length) {
    line(true, 'LLM answers', status.models.join(', '));
  } else {
    line(false, 'LLM answers', 'not set up — the built-in engine answers instead');
  }
  if (!status.models.length) {
    info('The built-in engine handles calc/text commands, questions about AAP, and short');
    info('coding/security/design/data tips. LLM answers switch on automatically once a model');
    info('is installed (ollama pull llama3.2:3b) — no restart needed.');
  } else if (MODELS.some((m) => !status.models.includes(m.name))) {
    info('Missing models fall back to the default model automatically.');
  }
  console.log(`\n${bold('Next')}`);
  console.log(`  ${teal('npm start')}                          ${dim('→ http://localhost:3000')}`);
  console.log(`  ${dim('The first start prints generated admin/demo passwords once — save them.')}`);
  console.log(`  ${teal('python3 client.py')}                  ${dim('→ terminal client (needs a key from the dashboard)')}\n`);
}

(async () => {
  console.log(`${bold('AAP setup')} ${dim('— checks this machine and asks before any large download')}`);
  checkNode();
  if (status.node) installNodeDeps();
  await checkPython();
  await checkMongo();
  const installed = await checkOllama();
  await checkModels(installed);
  summary();
})().catch((e) => {
  console.error(red(`Setup failed: ${e.message}`));
  process.exit(1);
});
