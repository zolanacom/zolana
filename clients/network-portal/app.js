import {number, empty, table, detail, validators, validatorDetail, build, status, ageObservation, networkPresentation} from './views.js';

const $ = id => document.getElementById(id);
const routes = new Set(['network','explorer','validators','build','status']);
const state = {route:'network', kind:'blocks', network:null, receivedAt:0, receivedWall:0, items:[], itemsKind:null, next:null, request:0, showingDetail:false, invalidRoute:false};
const descriptions = {network:'Read the public side of private payments.',explorer:'Search public evidence. Shielded payment details stay private.',validators:'Public voting-account observations, with their limits made clear.',build:'Implemented today, required next, and ideas for later.',status:'Current observations and the path to broader access.'};
async function api(path) {
  const controller = new AbortController();
  const timer = setTimeout(()=>controller.abort(), 8000);
  try {
    const response = await fetch(path, {cache:'no-store', signal:controller.signal, credentials:'same-origin'});
    if (!response.ok) throw new Error('The selected history is unavailable. Try again or choose another indexed record.');
    return await response.json();
  } finally { clearTimeout(timer); }
}
function notice(message = '') { $('notice').textContent = message; }
function markUnavailable() {
  state.network={...state.network,phase:'unknown',source:state.network?.source==='live-feed'?'saved-feed':state.network?.source || 'not-connected',feed_error:true};
  updateNetwork();
}
function receiveNetwork(network) {
  state.receivedAt=performance.now(); state.receivedWall=Date.now()/1000;
  state.network=ageObservation(network,0,state.receivedWall); updateNetwork();
}
function expireNetwork() {
  const aged=ageObservation(state.network,performance.now()-state.receivedAt,state.receivedWall);
  if (aged!==state.network) { state.network=aged; updateNetwork(); }
}
function busy(value) {
  $('refresh').disabled=value; $('load-more').disabled=value;
  if (value) $('view').setAttribute('aria-busy','true'); else $('view').removeAttribute('aria-busy');
}
function updateNetwork() {
  const network=state.network,display=networkPresentation(network);
  $('phase').textContent=display.phase;
  $('phase-dot').className=`status-dot ${display.live?'running':'unknown'}`;
  $('hero-phase').textContent=display.phase;
  $('hero-phase-dot').className=`status-dot ${display.live?'running':'unknown'}`;
  $('slot').textContent=number(network.last_observed_slot);
  $('slot').title=network.observed_at?`Observation: ${new Date(network.observed_at*1000).toLocaleString()}`:'No finality observation';
  $('network-environment').textContent=display.environment;
  $('history-state').textContent=display.history;
  $('source-note').textContent=display.sourceNote;
  for (const label of document.querySelectorAll('[data-network-phase]')) {
    label.textContent=display.phase;
    if (label.classList.contains('badge')) label.classList.toggle('verified',display.live);
  }
  for (const label of document.querySelectorAll('[data-network-history]')) label.textContent=display.history;
  for (const label of document.querySelectorAll('[data-network-observation-note]')) label.textContent=display.observationNote;
  $('wallet-description').textContent=network.wallet_genesis_hash&&network.genesis_hash&&network.wallet_genesis_hash!==network.genesis_hash?'The saved wallet observation uses a different network identity from this explorer. Preserve its network settings and compare the full genesis hash before making a payment.':'Open the browser wallet on this site to create or restore your encrypted wallet. Admission and test funding depend on its bound invited-network profile.';
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
  if (state.network.source === 'not-connected') {
    $('view').innerHTML = empty('Public history is not connected.', state.network.phase === 'paused' ? 'Validators are paused. Connect a public history source to inspect retained activity. Your wallet stays separate on this device.' : 'Connect retained public history to inspect recorded blocks and transactions.');
  } else $('view').innerHTML = table(state.items, state.kind);
  $('load-more').hidden = state.next === null;
}
async function activity(append = false, query = '') {
  const ticket = ++state.request;
  busy(true);
  if (state.itemsKind !== state.kind || query) $('view').innerHTML=empty(query ? 'Looking up public history' : 'Reading public activity','Checking the connected public source.');
  try {
    const network = await api('/api/network');
    if (ticket !== state.request) return;
    receiveNetwork(network);
    if (network.source === 'not-connected') { state.items=[]; state.next=null; renderActivity(); return; }
    if (query) return await lookup(query,ticket);
    const page = await api(`/api/${state.kind}?limit=8${append && state.next !== null ? `&before=${encodeURIComponent(state.next)}` : ''}`);
    if (ticket !== state.request) return;
    if (!Array.isArray(page.items)) throw new Error('The activity response could not be read. Try again.');
    state.items = append ? [...state.items,...page.items] : page.items; state.itemsKind=state.kind; state.next = page.next ?? null; renderActivity();
    if (append) notice('More recorded activity loaded.');
  } catch (error) {
    if (ticket !== state.request) return;
    const hadNetwork=Boolean(state.network); markUnavailable();
    notice(error.name === 'AbortError' ? 'The request took too long. Try again when the network service is available.' : error.message);
    if (!hadNetwork || state.itemsKind !== state.kind || query) $('view').innerHTML = empty('This view is unavailable.', 'The public portal could not read the selected public history. Your wallet and its saved payment state remain separate.',true);
  } finally { if (ticket === state.request) busy(false); }
}
function validQuery(query) { return (/^[0-9]{1,16}$/.test(query) && Number.isSafeInteger(Number(query))) || /^[1-9A-HJ-NP-Za-km-z]{32,88}$/.test(query); }
async function lookup(query,ticket) {
  if (!validQuery(query)) { $('view').innerHTML=empty('Check your search.','Enter a slot number, block hash or transaction signature.'); notice('This search format is not supported.'); return; }
  const result = await api(`/api/search?q=${encodeURIComponent(query)}`);
  if (ticket !== state.request) return;
  state.showingDetail=true; $('view').removeAttribute('role'); $('view').removeAttribute('aria-labelledby');
  $('view').innerHTML=detail(result.kind,result.value); $('view').focus({preventScroll:true}); $('load-more').hidden=true;
}
async function route() {
  const [value, encodedQuery='', extra] = location.hash.slice(1).split('/');
  let query='';
  try { query=decodeURIComponent(encodedQuery); } catch { query='invalid'; }
  const knownRoute=routes.has(value) || !value;
  state.route = routes.has(value) ? value : 'network';
  const ticket=++state.request; notice(); busy(false);
  document.body.dataset.page=state.route;
  for (const link of document.querySelectorAll('[data-route]')) {
    if (link.dataset.route === state.route && knownRoute) link.setAttribute('aria-current','page'); else link.removeAttribute('aria-current');
  }
  const explorer = state.route === 'network' || state.route === 'explorer';
  $('hero').hidden = state.route !== 'network' || !knownRoute;
  $('network-context').hidden = state.route !== 'network' || !knownRoute;
  $('explorer-toolbar').hidden = !explorer || !knownRoute; $('search-form').hidden = !explorer || !knownRoute; $('load-more').hidden=true;
  $('page-title').textContent = {network:'Inside the network',explorer:'Explorer',validators:'Validators',build:'Build on Zolana',status:'Network status'}[state.route];
  $('page-title').setAttribute('aria-level',state.route === 'network' && knownRoute ? '2' : '1');
  $('page-description').textContent=descriptions[state.route];
  document.title = state.route === 'network' ? 'Zolana — Private money. Public network.' : `${$('page-title').textContent} — Zolana`;
  state.invalidRoute=!knownRoute || extra !== undefined || (query && !['explorer','validators'].includes(state.route));
  if (state.invalidRoute) {
    $('page-title').textContent='Page not found'; $('page-description').textContent='Choose a destination from the navigation.';
    document.title='Page not found — Zolana';
    $('view').innerHTML=empty('This page does not exist.','Return to Network, search the Explorer, or check the current network status.'); return;
  }
  if (explorer) { $('search').value=query; return activity(false,query); }
  state.showingDetail=false;
  $('view').removeAttribute('role'); $('view').removeAttribute('aria-labelledby');
  $('view').innerHTML=empty('Reading network information', 'Checking the connected public source.'); busy(true);
  try {
    const network = await api('/api/network');
    if (ticket !== state.request) return;
    receiveNetwork(network);
    $('view').innerHTML = state.route === 'validators' ? query ? validatorDetail(state.network,query) : validators(state.network) : state.route === 'status' ? status(state.network) : build(state.network);
  } catch {
    if (ticket !== state.request) return;
    markUnavailable();
    $('view').innerHTML=empty('Network information is unavailable.','The public portal service could not be reached. Try again; your device-local wallet remains separate.',true);
  } finally { if (ticket === state.request) busy(false); }
}
function search(value) {
  const query = String(value).trim(); notice();
  if (!validQuery(query)) { notice('Enter a slot number, block hash or transaction signature.'); $('search').setAttribute('aria-invalid','true'); $('search').focus(); return; }
  $('search').removeAttribute('aria-invalid');
  if (location.hash === `#explorer/${query}`) route(); else location.hash=`explorer/${encodeURIComponent(query)}`;
}
function showDialog(id) { $(id).showModal(); }
document.querySelector('.skip').addEventListener('click',event=>{event.preventDefault(); $('main').focus(); $('main').scrollIntoView({block:'start'});});
$('search-form').addEventListener('submit', event=>{event.preventDefault(); search($('search').value);});
$('search').addEventListener('input',()=>$('search').removeAttribute('aria-invalid'));
$('refresh').addEventListener('click',route);
$('load-more').addEventListener('click',()=>activity(true));
for (const kind of ['blocks','transactions']) {
  $(`${kind}-tab`).addEventListener('click',()=>{state.kind=kind;state.next=null;notice();showTabs();if(location.hash.includes('/')) location.hash='explorer'; else activity();});
  $(`${kind}-tab`).addEventListener('keydown', event=>{
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault(); const next = event.key === 'Home' ? 'blocks' : event.key === 'End' ? 'transactions' : kind === 'blocks' ? 'transactions' : 'blocks'; $(`${next}-tab`).click(); $(`${next}-tab`).focus();
  });
}
for (const button of document.querySelectorAll('[data-global-privacy]')) button.addEventListener('click',()=>showDialog('privacy-dialog'));
for (const button of document.querySelectorAll('[data-close]')) button.addEventListener('click',()=>button.closest('dialog').close());
$('view').addEventListener('click',async event=>{
  const button=event.target.closest('button'); if (!button) return;
  if (button.hasAttribute('data-query')) { $('search').value=button.dataset.query; return search(button.dataset.query); }
  if (button.hasAttribute('data-back')) { location.hash='explorer'; return; }
  if (button.hasAttribute('data-retry')) return route();
  if (button.hasAttribute('data-privacy')) return showDialog('privacy-dialog');
  if (button.hasAttribute('data-wallet')) return showDialog('wallet-dialog');
  if (button.hasAttribute('data-copy')) {
    try { await navigator.clipboard.writeText(button.dataset.copy); notice('Copied to clipboard.'); }
    catch { notice('Clipboard is unavailable. Select the full value displayed in this view to copy it.'); }
  }
});
window.addEventListener('hashchange',()=>{route();window.scrollTo({top:0,behavior:'instant'});});
document.addEventListener('keydown',event=>{
  if (event.key==='/' && !event.ctrlKey && !event.metaKey && !event.altKey && !event.target.closest('input,textarea,select,[contenteditable=true]') && !$('search-form').hidden && !document.querySelector('dialog[open]')) { event.preventDefault(); $('search').focus(); }
});
let informationRefreshing=false;
async function refreshInformation(){
  if (informationRefreshing) return;
  informationRefreshing=true;
  const ticket=state.request;
  try {
    const network=await api('/api/network');
    if (ticket!==state.request) return;
    receiveNetwork(network);
    if (!$('content').contains(document.activeElement) && !document.querySelector('dialog[open]')) {
      $('view').innerHTML=state.route==='validators'?validators(state.network):status(state.network);
    }
  } catch { if (ticket===state.request) markUnavailable(); }
  finally { informationRefreshing=false; }
}
function refreshIdle(){
  expireNetwork();
  const explorer=state.route==='network' || state.route==='explorer';
  if (state.invalidRoute || document.hidden || document.querySelector('dialog[open]') || $('view').getAttribute('aria-busy') === 'true' || (explorer && (state.showingDetail || state.items.length>8)) || $('content').contains(document.activeElement)) return;
  if ((state.route==='network' || state.route==='explorer') && !location.hash.includes('/')) activity();
  else if (['validators','status'].includes(state.route) && !location.hash.includes('/')) refreshInformation();
}
setInterval(expireNetwork,1000);
setInterval(refreshIdle,5000);
document.addEventListener('visibilitychange',()=>{ expireNetwork(); if (!document.hidden) refreshIdle(); });
route();

/* The path is a protocol illustration, never a transaction or network metric.
   Its finite replay and native-scroll timeline share the same paused SVG tracks. */
function setupMotion(){
  const scene=document.getElementById('path-scene'),hero=document.getElementById('hero');
  const statement=document.getElementById('principle-title'),button=document.getElementById('replay');
  const status=document.getElementById('illustration-status'),reduced=matchMedia('(prefers-reduced-motion: reduce)');
  const tracks=[],reading=[],all=new Set(),originals=new Map();
  const clamp=value=>Math.max(0,Math.min(1,value));
  let observer,visible=true,frame=0,scrollFrame=0,resizeTimer=0,width=innerWidth,auto=false,manual=false,start=0,progress=1,last=0,entered=false,disposed=false,scrolled=false,previousY=scrollY;

  function animation(element,keyframes,options={}){
    const value=element.animate(keyframes,{duration:1000,fill:'both',...options});all.add(value);return value;
  }
  function track(element,keyframes){const value=animation(element,keyframes,{easing:'linear'});value.pause();value.currentTime=1000;tracks.push(value);return value;}
  function remember(element){if(!originals.has(element))originals.set(element,{html:element.innerHTML,label:element.getAttribute('aria-label')});}
  function words(element){
    remember(element);const parts=[];
    function visit(node){if(node.nodeType===Node.TEXT_NODE)parts.push(node.textContent);else if(node.nodeName==='BR')parts.push('\n');else for(const child of node.childNodes)visit(child);}
    for(const child of element.childNodes)visit(child);
    const text=parts.join('').replace(/[\t ]+/g,' ').trim(),fragment=document.createDocumentFragment(),units=[];
    element.setAttribute('aria-label',text.replace(/\s+/g,' '));
    for(const token of text.split(/(\n| +)/)){
      if(!token)continue;if(token==='\n'){fragment.append(document.createElement('br'));continue;}if(/^ +$/.test(token)){fragment.append(document.createTextNode(' '));continue;}
      const mask=document.createElement('span'),unit=document.createElement('span');mask.className='word-mask';mask.setAttribute('aria-hidden','true');unit.className='word-unit';unit.textContent=token;mask.append(unit);fragment.append(mask);units.push(unit);
    }
    element.replaceChildren(fragment);return units;
  }
  function lines(element){
    const units=words(element),groups=[];
    units.forEach(unit=>{const top=unit.parentElement.getBoundingClientRect().top;let group=groups.at(-1);if(!group||Math.abs(group.top-top)>3){group={top,units:[]};groups.push(group);}group.units.push(unit.parentElement);});
    const fragment=document.createDocumentFragment(),result=[];
    groups.forEach(group=>{const mask=document.createElement('span'),line=document.createElement('span');mask.className='line-mask';mask.setAttribute('aria-hidden','true');line.className='line-unit';group.units.forEach((unit,index)=>{if(index)line.append(document.createTextNode(' '));line.append(unit);});mask.append(line);fragment.append(mask);result.push(line);});
    element.replaceChildren(fragment);return result;
  }
  function setProgress(value){progress=clamp(value);tracks.forEach(track=>track.currentTime=progress*1000);scene.dataset.progress=progress.toFixed(3);}
  function stop(){auto=false;if(frame)cancelAnimationFrame(frame);frame=0;}
  function restore(){
    stop();observer?.disconnect();all.forEach(value=>value.cancel());all.clear();tracks.length=0;reading.length=0;
    originals.forEach((value,element)=>{element.innerHTML=value.html;if(value.label===null)element.removeAttribute('aria-label');else element.setAttribute('aria-label',value.label);});
    document.body.classList.remove('motion-ready');
  }
  function build(){
    if(disposed)return;restore();if(hero.hidden)return;document.body.classList.toggle('motion-reduced',reduced.matches);
    if(reduced.matches||typeof Element.prototype.animate!=='function'){scene.dataset.progress='1.000';return;}
    try{
      document.querySelectorAll('.private-draw').forEach(element=>track(element,[{offset:0,strokeDashoffset:'1000'},{offset:.45,strokeDashoffset:'0'},{offset:1,strokeDashoffset:'0'}]));
      document.querySelectorAll('.public-draw').forEach(element=>track(element,[{offset:0,strokeDashoffset:'1000'},{offset:.45,strokeDashoffset:'1000'},{offset:1,strokeDashoffset:'0'}]));
      document.querySelectorAll('.verification-mark').forEach(element=>{
        const position=Number(element.dataset.verify),begin=.58+position*.14;
        track(element,[{offset:0,opacity:.42,strokeDashoffset:'0'},{offset:begin,opacity:.42,strokeDashoffset:'0'},{offset:Math.min(1,begin+.12),opacity:1,strokeDashoffset:'0'},{offset:1,opacity:1,strokeDashoffset:'0'}]);
      });
      document.querySelectorAll('.z-boundary').forEach(element=>track(element,[{offset:0,strokeOpacity:.65},{offset:.35,strokeOpacity:1},{offset:1,strokeOpacity:1}]));
      document.querySelectorAll('.display-line').forEach((element,row)=>words(element).forEach((unit,index)=>animation(unit,[{transform:'scale(.75)',opacity:.88},{transform:'scale(1)',opacity:1}],{duration:650,delay:row*80+index*55,easing:'cubic-bezier(.22,1,.36,1)'})));
      const entries=[];
      lines(statement).forEach((line,index)=>{
        const value=animation(line,[{transform:'scaleX(.8)',visibility:'hidden'},{transform:'scaleX(1)',visibility:'visible'}],{duration:650,delay:index*70,easing:'cubic-bezier(.22,1,.36,1)'});value.pause();value.currentTime=entered?650+index*70:0;entries.push(value);
        const sweep=animation(line,[{backgroundPosition:'100% 0%'},{backgroundPosition:'0% 0%'}],{duration:1000,easing:'linear'});sweep.pause();sweep.currentTime=0;reading.push({line,value:sweep});
      });
      observer=new IntersectionObserver(changes=>{if(changes.some(change=>change.isIntersecting)){entered=true;entries.forEach(value=>value.play());observer.disconnect();}},{rootMargin:'0px 0px -12% 0px',threshold:.05});if(!entered)observer.observe(statement);
      document.body.classList.add('motion-ready');setProgress(1);schedule();
    }catch{restore();scene.dataset.progress='1.000';}
  }
  function draw(now){
    frame=0;if(!auto||disposed||document.hidden||!visible||reduced.matches)return;
    if(!start)start=now-progress*1800;
    if(now-last>=1000/30){last=now;setProgress((now-start)/1800);}
    if(progress<1)frame=requestAnimationFrame(draw);else{auto=false;if(manual)status.textContent='Illustration complete: private details stay concealed while public payment evidence remains.';}
  }
  function replay(user=true){
    stop();manual=user;status.textContent=user?'Playing the protocol illustration. No payment is being sent.':'';
    if(reduced.matches||!tracks.length){setProgress(1);if(user)status.textContent='Private details are concealed; the network verifies public payment evidence. Static illustration.';return;}
    setProgress(0);start=0;last=0;auto=true;if(visible&&!document.hidden)frame=requestAnimationFrame(draw);
  }
  function update(){
    scrollFrame=0;if(disposed||document.hidden||hero.hidden)return;
    if(!auto&&scrolled&&!reduced.matches&&tracks.length){const rect=hero.getBoundingClientRect();setProgress(clamp(-rect.top/Math.max(rect.height*.62,1)));}
    reading.forEach(row=>row.value.currentTime=clamp((innerHeight*.80-row.line.parentElement.getBoundingClientRect().top)/(innerHeight*.42))*1000);
  }
  function schedule(){if(!scrollFrame&&!disposed)scrollFrame=requestAnimationFrame(update);}
  function scroll(){if(scrollY!==previousY){previousY=scrollY;scrolled=true;stop();}schedule();}
  function resize(){if(innerWidth!==width){width=innerWidth;clearTimeout(resizeTimer);resizeTimer=setTimeout(build,100);}schedule();}
  function visibility(){
    if(document.hidden){if(frame)cancelAnimationFrame(frame);frame=0;if(scrollFrame)cancelAnimationFrame(scrollFrame);scrollFrame=0;}
    else{if(auto&&visible){start=0;frame=requestAnimationFrame(draw);}schedule();}
  }
  function preference(){build();}
  function routeMotion(){if(hero.hidden){stop();return;}build();}
  addEventListener('hashchange',routeMotion);
  const intersection=new IntersectionObserver(changes=>{visible=changes[0].isIntersecting;if(!visible&&frame){cancelAnimationFrame(frame);frame=0;}else if(visible&&auto&&!document.hidden){start=0;frame=requestAnimationFrame(draw);}},{threshold:.01});intersection.observe(scene);
  const play=()=>replay(true);button.addEventListener('click',play);addEventListener('scroll',scroll,{passive:true});addEventListener('resize',resize,{passive:true});document.addEventListener('visibilitychange',visibility);reduced.addEventListener('change',preference);
  if(document.fonts?.ready)document.fonts.ready.then(()=>{build();replay(false);});else{build();replay(false);}
  return {destroy(){disposed=true;restore();if(scrollFrame)cancelAnimationFrame(scrollFrame);clearTimeout(resizeTimer);intersection.disconnect();button.removeEventListener('click',play);removeEventListener('scroll',scroll);removeEventListener('resize',resize);removeEventListener('hashchange',routeMotion);document.removeEventListener('visibilitychange',visibility);reduced.removeEventListener('change',preference);}};
}

setupMotion();
