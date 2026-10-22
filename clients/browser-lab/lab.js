const $ = id => document.getElementById(id);
let worker, generation = 0, current = null, nextId = 0, attempts = 0, config;
let heartbeatAt = performance.now(), maxGap = 0;
const fmt = ms => Number.isFinite(ms) ? `${(ms / 1000).toFixed(3)} s` : '—';
const threads = () => Number($('backend').value);
const ready = () => threads() ? config?.parallel_ready : config?.wasm_ready;
function status(label, detail) { $('status').textContent = label; $('detail').textContent = detail; }
function controls(busy) { $('run').disabled = busy || !ready(); $('abort').disabled = !busy; }
function checks(values) { $('checks').replaceChildren(...values.map(text => { const el = document.createElement('li'); el.textContent = text; return el; })); }
setInterval(() => {
  const now = performance.now();
  if (current) { maxGap = Math.max(maxGap, now - heartbeatAt); $('heartbeat').textContent = `${Math.round(maxGap)} ms`; }
  heartbeatAt = now;
}, 50);
function freshWorker() {
  generation += 1; worker?.terminate(); worker = null;
  if (current) { current.abort.abort(); finish('Aborted', 'Worker terminated. No wallet or network operation was involved.'); }
  attempts = 0; $('run').textContent = 'Run first proof';
  for (const id of ['load', 'prepare', 'proof', 'decrypt', 'memory', 'heartbeat']) $(id).textContent = '—';
  $('native').textContent = 'Not checked';
  status(ready() ? 'Ready' : 'Build needed', ready() ? 'Fresh worker. Start a synthetic first-use attempt.' : 'The selected WASM build is not available yet. Reload this page after the local build is ready.');
  controls(false);
}
function finish(outcome, detail) {
  if (!current) return;
  const record = current; current = null;
  $('empty')?.remove(); const tr = document.createElement('tr');
  [record.label, fmt(record.load_ms), fmt(record.prepare_ms), fmt(record.proof_ms), fmt(record.decrypt_ms), fmt(record.native_ms), outcome].forEach(text => { const td = document.createElement('td'); td.textContent = text; tr.append(td); });
  $('runs').prepend(tr); controls(false); status(outcome, detail);
}
async function handleMessage(event, workerGeneration) {
  const data = event.data;
  if (workerGeneration !== generation || !current || data.id !== current.id) return;
  if (data.type === 'stage') { status('Running', data.message); return; }
  if (data.type === 'error') { worker?.terminate(); worker = null; finish('Failed', data.message); return; }
  if (data.type !== 'result') return;
  const record = current;
  Object.assign(record, data.metrics);
  $('load').textContent = fmt(record.load_ms); $('prepare').textContent = fmt(record.prepare_ms); $('proof').textContent = fmt(record.proof_ms); $('decrypt').textContent = fmt(record.decrypt_ms);
  $('memory').textContent = Number.isFinite(record.memory_bytes) ? `${(record.memory_bytes / 1048576).toFixed(1)} MiB` : 'Unavailable';
  checks(data.checks);
  if (!config.native_checker_ready) { $('native').textContent = 'Unavailable'; finish('Browser only', 'Browser checks completed. Configure a native checker before claiming native compatibility.'); return; }
  status('Checking native parity', 'Only the public synthetic fixture is sent to the configured native reference checker.');
  try {
    const start = performance.now();
    const response = await fetch('/api/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data.public_fixture), signal: record.abort.signal });
    const result = await response.json();
    if (current !== record || workerGeneration !== generation) return;
    record.native_ms = performance.now() - start;
    if (!response.ok || result.ok !== true) throw new Error(result.error || 'Native checker rejected the synthetic fixture.');
    $('native').textContent = 'Verified';
    checks([...data.checks, ...result.checks]);
    finish('Passed', 'Synthetic browser proof and decryption agree with the native reference. This is not a blockchain payment.');
  } catch (error) {
    if (current !== record) return;
    $('native').textContent = 'Failed'; finish('Failed', error.name === 'AbortError' ? 'Local check interrupted.' : error.message);
  }
}
$('run').addEventListener('click', () => {
  if (current || !ready()) return;
  if (!worker) attempts = 0;
  current = { id: ++nextId, label: `${attempts++ ? `Warm ${attempts - 1}` : 'First'} · ${threads() || 1} thread${threads() ? 's' : ''}`, abort: new AbortController() };
  maxGap = 0; heartbeatAt = performance.now(); controls(true); $('native').textContent = 'Waiting';
  if (!worker) {
    worker = new Worker('/worker.js', { type: 'module' }); const workerGeneration = generation;
    worker.addEventListener('message', event => handleMessage(event, workerGeneration));
    worker.addEventListener('error', () => { if (workerGeneration !== generation) return; worker?.terminate(); worker = null; finish('Failed', 'Worker failed. Check that the local WASM build matches this lab.'); });
  }
  status('Running', 'Loading the synthetic cryptographic core in a dedicated worker…');
  worker.postMessage({ type: 'run', id: current.id, threads: threads() }); $('run').textContent = 'Run warm proof';
});
$('abort').addEventListener('click', freshWorker); $('restart').addEventListener('click', freshWorker);
$('backend').addEventListener('change', freshWorker);
try {
  const response = await fetch('/api/config'); if (!response.ok) throw new Error('Local configuration refused.');
  config = await response.json();
  for (const option of $('backend').options) {
    const count = Number(option.value);
    if (count) option.disabled = !config.parallel_ready || !crossOriginIsolated || typeof SharedArrayBuffer !== 'function' || count > Math.min(8, navigator.hardwareConcurrency || 1);
  }
  freshWorker();
} catch (error) { status('Unavailable', error.message); controls(false); }
