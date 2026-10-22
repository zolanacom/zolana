// Synthetic-only adapter. No wallet seed, password, viewing key or gateway API.
let core, wasm, busy = false, activeThreads;
const stage = (id, message) => postMessage({ type: 'stage', id, message });
const parse = (text, format) => {
  const value = JSON.parse(text);
  if (!value || value.format !== format || value.fixture_only !== true) throw new Error('Synthetic core contract mismatch.');
  return value;
};
function publicFixture(value) {
  const keys = ['format', 'fixture_only', 'network_hex', 'funding_payload_hex', 'payment_payload_hex', 'envelope_hex', 'timings_ms'];
  if (Object.keys(value).sort().join() !== keys.sort().join()) throw new Error('Unexpected public fixture fields.');
  for (const name of ['network_hex', 'funding_payload_hex', 'payment_payload_hex', 'envelope_hex']) {
    if (typeof value[name] !== 'string' || !/^[0-9a-f]+$/.test(value[name]) || value[name].length % 2) throw new Error('Invalid public fixture encoding.');
  }
  if (value.network_hex.length !== 64) throw new Error('Invalid synthetic network identity.');
  const times = value.timings_ms;
  if (!times || Object.keys(times).sort().join() !== ['funding_proof', 'local_verify', 'payment_proof'].join() ||
      !Object.values(times).every(ms => Number.isFinite(ms) && ms >= 0)) throw new Error('Invalid synthetic timing record.');
  return value;
}
self.addEventListener('message', async event => {
  const { type, id, threads = 0 } = event.data || {};
  if (type !== 'run' || !Number.isSafeInteger(id) || busy) return;
  busy = true;
  try {
    if (![0, 4, 8].includes(threads) || threads > Math.min(8, navigator.hardwareConcurrency || 1)) throw new Error('Unsupported bounded synthetic thread count.');
    if (activeThreads !== undefined && activeThreads !== threads) throw new Error('Restart the worker before changing thread counts.');
    let load_ms = 0;
    if (!core) {
      stage(id, 'Loading Orchard 0.16 WASM. Browser caches may already contain the local assets…');
      const start = performance.now();
      core = threads ? await import('/wasm-parallel/browser_core.js') : await import('/wasm/browser_core.js');
      wasm = await core.default();
      const version = parse(core.version(), 'zolana-browser-core-version-v1');
      if (version.orchard !== '0.16.0' || version.circuit !== 'orchard_v2' || version.multicore !== Boolean(threads)) throw new Error('Unexpected Orchard feasibility build.');
      if (threads) {
        if (!crossOriginIsolated || typeof SharedArrayBuffer !== 'function' || typeof core.initThreadPool !== 'function') throw new Error('Threaded WASM requires cross-origin isolation and the reviewed thread-pool export.');
        stage(id, `Starting the ${threads}-thread synthetic Rayon pool…`);
        let startupTimer;
        try {
          await Promise.race([core.initThreadPool(threads), new Promise((_, reject) => { startupTimer = setTimeout(() => reject(new Error('Synthetic thread-pool startup timed out.')), 15000); })]);
        } finally { clearTimeout(startupTimer); }
      }
      activeThreads = threads;
      load_ms = performance.now() - start;
    }
    stage(id, 'Preparing prover keys inside the worker. The page remains interactive; Abort terminates this worker.');
    let start = performance.now();
    const preparation = parse(core.prepare_prover(), 'zolana-browser-prover-ready-v1');
    const prepare_ms = performance.now() - start;
    stage(id, 'Building two disposable synthetic proofs: funding and a shielded-fee payment. No network transaction is sent.');
    start = performance.now();
    const fixture = publicFixture(parse(core.synthetic_fixture(), 'zolana-browser-synthetic-fixture-v1'));
    const proof_ms = performance.now() - start;
    stage(id, 'Decrypting the synthetic recipient and change notes with worker-local keys…');
    start = performance.now();
    const decryption = parse(core.decrypt_fixture(), 'zolana-browser-decryption-v1');
    const decrypt_ms = performance.now() - start;
    if (decryption.recipient_value !== 40 || decryption.change_value !== 57 || decryption.recipient_note_count !== 1 ||
        decryption.change_note_count !== 1 || decryption.wrong_key_notes !== 0 || decryption.witness_root_verified !== true) {
      throw new Error('Synthetic local decryption or witness check failed.');
    }
    postMessage({ type: 'result', id, public_fixture: fixture,
      metrics: { load_ms, prepare_ms, proof_ms, decrypt_ms, memory_bytes: wasm?.memory?.buffer.byteLength },
      checks: [
        `Orchard 0.16 / Orchard v2, ${threads ? `${threads}-thread` : 'single-thread'} WASM; ${preparation.cached ? 'cached' : 'fresh'} prover keys.`,
        `Synthetic funding proof: ${(fixture.timings_ms.funding_proof / 1000).toFixed(3)} s; payment proof: ${(fixture.timings_ms.payment_proof / 1000).toFixed(3)} s.`,
        'Local recipient note = 40; sender change = 57; wrong key finds no note.',
        'Local witness root verified. Only public synthetic proof packets leave the worker.'
      ] });
  } catch (error) {
    postMessage({ type: 'error', id, message: String(error?.message || 'Synthetic worker failed.').slice(0, 400) });
  } finally { busy = false; }
});
