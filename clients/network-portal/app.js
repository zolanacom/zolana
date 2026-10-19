import {number, empty, table, detail, validators, build} from './views.js';

const $ = id => document.getElementById(id);
const routes = new Set(['network','explorer','validators','build']);
const state = {route:'network', kind:'blocks', network:null, items:[], next:null, request:0, showingDetail:false};
async function api(path) {
  const controller = new AbortController();
  const timer = setTimeout(()=>controller.abort(), 8000);
  try {
    const response = await fetch(path, {cache:'no-store', signal:controller.signal, credentials:'same-origin'});
    if (!response.ok) throw new Error('The selected history is unavailable. Refresh to try again.');
    return await response.json();
  } finally { clearTimeout(timer); }
}
function notice(message = '') { $('notice').textContent = message; }
function updateNetwork() {
  const network = state.network;
  const labels = {paused:'Validators paused',running:'Validator service running',unknown:'Status unavailable',starting:'Network starting',replaying:'Replaying ledger',syncing:'Network syncing',retaining:'Retaining history',blocked:'Network blocked',failed:'Network stopped'};
  $('phase').textContent = labels[network.phase] || 'Status unavailable';
  $('phase-dot').className = `status-dot ${network.phase === 'running' ? 'running' : network.phase === 'paused' ? '' : 'unknown'}`;
  $('slot').textContent = number(network.last_observed_slot);
  $('slot').title = network.observed_at ? `Historical observation: ${new Date(network.observed_at*1000).toLocaleString()}` : 'No finality observation';
  $('wallet-description').textContent = network.wallet_genesis_hash && network.genesis_hash && network.wallet_genesis_hash !== network.genesis_hash ? 'Your saved wallet uses a different local test network from this explorer. Open it with its existing network settings. No funds or wallet data will move.' : 'Open the device-local wallet to manage your encrypted wallet, test coins and private payments. Confirm its pinned network before making a payment.';
  $('source-note').textContent = network.source === 'saved-history' ? `Saved public history · through slot ${number(network.history_tip)} · ${number(network.recorded_blocks)} recorded blocks. Not a live feed.` : 'No history source connected. No live data is implied.';
}
function showTabs() {
  for (const kind of ['blocks','transactions']) {
    const selected = state.kind === kind;
    $(`${kind}-tab`).setAttribute('aria-selected', String(selected));
    $(`${kind}-tab`).tabIndex = selected ? 0 : -1;
  }
  $('view').setAttribute('role','tabpanel');
  $('view').setAttribute('aria-labelledby',`${state.kind}-tab`);
}
function renderActivity() {
  state.showingDetail = false;
  showTabs();
  if (state.network.source !== 'saved-history') {
    $('view').innerHTML = empty('Nothing hidden about the network.', state.network.phase === 'paused' ? 'Validators are paused. Finalized activity appears here when a public history source is connected.' : 'Connect retained public history to inspect recorded blocks and transactions.');
  } else $('view').innerHTML = table(state.items, state.kind);
  $('load-more').hidden = state.next === null;
}
async function activity(append = false) {
  const ticket = ++state.request;
  $('refresh').disabled = true; $('load-more').disabled = true;
  $('view').setAttribute('aria-busy','true');
  try {
    const network = await api('/api/network');
    if (ticket !== state.request) return;
    state.network = network; updateNetwork();
    if (network.source !== 'saved-history') { state.items=[]; state.next=null; renderActivity(); return; }
    const page = await api(`/api/${state.kind}?limit=8${append && state.next !== null ? `&before=${state.next}` : ''}`);
    if (ticket !== state.request) return;
    state.items = append ? [...state.items,...page.items] : page.items; state.next = page.next; renderActivity();
    if (append) notice('More recorded activity loaded.');
  } catch (error) {
    if (ticket !== state.request) return;
    notice(error.name === 'AbortError' ? 'The request took too long. Refresh to try again.' : error.message);
    if (!state.network) $('view').innerHTML = empty('The portal is offline.', 'The local portal service is unavailable. Your wallet is separate and remains on this device.');
  } finally {
    if (ticket === state.request) { $('refresh').disabled=false; $('load-more').disabled=false; $('view').removeAttribute('aria-busy'); }
  }
}
async function route() {
  const [value, query] = location.hash.slice(1).split('/');
  if (!query) $('search').value='';
  state.route = routes.has(value) ? value : 'network';
  ++state.request; notice();
  for (const link of document.querySelectorAll('[data-route]')) {
    if (link.dataset.route === state.route) link.setAttribute('aria-current','page'); else link.removeAttribute('aria-current');
  }
  const explorer = state.route === 'network' || state.route === 'explorer';
  $('hero').hidden = state.route !== 'network';
  $('explorer-toolbar').hidden = !explorer; $('search-form').hidden = !explorer; $('load-more').hidden=true;
  $('page-title').textContent = {network:'Inside the network',explorer:'Explorer',validators:'The network behind Zolana',build:'Build on Zolana'}[state.route];
  document.title = `${state.route === 'network' ? 'Zolana — Private by protocol' : `${$('page-title').textContent} — Zolana`}`;
  if (explorer) {
    const currentHash=location.hash;
    await activity();
    if (query && location.hash === currentHash) { $('search').value=query; await search(query,false); }
    return;
  }
  $('view').removeAttribute('role'); $('view').removeAttribute('aria-labelledby');
  $('view').innerHTML=empty('Reading network information', 'Loading the selected local network view.');
  try {
    const selectedRoute = state.route;
    const network = await api('/api/network');
    if (state.route !== selectedRoute) return;
    state.network=network; updateNetwork();
    $('view').innerHTML = state.route === 'validators' ? validators(network) : build(network);
  } catch { notice('Network information is unavailable. Refresh the page to try again.'); }
}
async function search(value, navigate = true) {
  const query = String(value).trim(); notice();
  if (!/^(?:[0-9]{1,16}|[1-9A-HJ-NP-Za-km-z]{32,88})$/.test(query)) { notice('Enter a slot number, block hash or transaction signature.'); return; }
  if (!state.network || state.network.source !== 'saved-history') { notice('Saved history is not connected. No result can be checked yet.'); return; }
  if (navigate && location.hash !== `#explorer/${query}`) { location.hash=`explorer/${query}`; return; }
  const ticket = ++state.request;
  $('view').setAttribute('aria-busy','true'); $('load-more').hidden=true;
  try {
    const result = await api(`/api/search?q=${encodeURIComponent(query)}`);
    if (ticket !== state.request) return;
    state.showingDetail=true; $('view').innerHTML=detail(result.kind,result.value); $('view').focus({preventScroll:true});
  } catch { if (ticket === state.request) notice('The history lookup failed. Your search has not been sent to a public service.'); }
  finally { if (ticket === state.request) { $('view').removeAttribute('aria-busy'); $('refresh').disabled=false; } }
}
function showDialog(id) { $(id).showModal(); }
$('search-form').addEventListener('submit', event=>{event.preventDefault(); search($('search').value);});
$('refresh').addEventListener('click',route);
$('load-more').addEventListener('click',()=>activity(true));
for (const kind of ['blocks','transactions']) {
  $(`${kind}-tab`).addEventListener('click',()=>{state.kind=kind;state.next=null;notice();if(location.hash.includes('/')) location.hash='explorer'; else activity();});
  $(`${kind}-tab`).addEventListener('keydown', event=>{
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault(); const next = event.key === 'Home' ? 'blocks' : event.key === 'End' ? 'transactions' : kind === 'blocks' ? 'transactions' : 'blocks'; $(`${next}-tab`).click(); $(`${next}-tab`).focus();
  });
}
$('how-it-works').addEventListener('click',()=>showDialog('privacy-dialog'));
$('open-wallet').addEventListener('click',()=>showDialog('wallet-dialog'));
for (const button of document.querySelectorAll('[data-close]')) button.addEventListener('click',()=>button.closest('dialog').close());
$('view').addEventListener('click',async event=>{
  const button=event.target.closest('button'); if (!button) return;
  if (button.hasAttribute('data-query')) { $('search').value=button.dataset.query; return search(button.dataset.query); }
  if (button.hasAttribute('data-back')) { location.hash='explorer'; return; }
  if (button.hasAttribute('data-privacy')) return showDialog('privacy-dialog');
  if (button.hasAttribute('data-copy-genesis')) {
    if (!state.network?.genesis_hash) return notice('No network identity is connected.');
    try { await navigator.clipboard.writeText(state.network.genesis_hash); notice('Genesis hash copied.'); }
    catch { notice('Clipboard is unavailable. Select the genesis hash below to copy it.'); }
  }
});
window.addEventListener('hashchange',route);
route();
