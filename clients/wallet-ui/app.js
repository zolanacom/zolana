const screen = document.querySelector('#screen');
const notice = document.querySelector('#notice');
let progressTimer, progressLabel = '', progressStarted = 0;
let session = {}, password = '', address = '', balance = null, receipt = null, publicAddress = '', publicBalance = null, feeBalance = null, minimumPublicWithdrawal = null, busy = false, idle, grant = null, grantPoll, grantStarted = 0;
let balanceVerified = false, lastVerifiedAt = null;

function units(value) { return Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() : '—'; }
function syncState(text, state = '') {
  const indicator = document.getElementById('sync-state');
  if (indicator) { indicator.textContent = text; indicator.setAttribute?.('data-state', state); }
}
function settledSyncState() {
  if (screen.querySelector('#unlock-form')) return syncState('Password required');
  if (screen.querySelector('#create-form')) return syncState('Ready to create');
  if (screen.querySelector('#restore-form')) return syncState('Recovery file required');
  if (!password) return syncState(session.exists ? 'Password required' : 'Ready to create');
  if (screen.querySelector('#invite-form')) return syncState('Invitation required', 'pending');
  if (screen.querySelector('#download') && session.needs_backup) return syncState('Save your recovery', 'pending');
  if (session.pending || session.staging) return syncState(session.pending ? 'Saved payment needs attention' : 'Upload recovery required', 'pending');
  if (balanceVerified) return syncState(`Balance checked ${new Date(lastVerifiedAt).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}`, 'verified');
  return syncState('Balance not verified', 'error');
}
function invalid(ids, text) {
  for (const id of ids) {
    const field = document.getElementById(id);
    if (field) { field.setAttribute('aria-invalid', 'true'); field.setAttribute('aria-describedby', 'notice'); }
  }
  message(text, 'error');
  document.getElementById(ids[0])?.focus();
}

function message(text = '', kind = '') {
  notice.textContent = text; notice.className = kind;
  notice.setAttribute?.('role', kind === 'error' ? 'alert' : 'status');
  notice.setAttribute?.('aria-live', kind === 'error' ? 'assertive' : 'polite');
  if (kind === 'error') notice.scrollIntoView({ block: 'nearest' });
}
function setScreen(html) {
  clearTimeout(grantPoll);
  screen.innerHTML = html; message();
  const onboarding = screen.querySelector('#create-form, #restore-form, #unlock-form, #invite-form, #download');
  document.body.setAttribute('data-wallet-mode', onboarding || !password ? 'setup' : 'active');
  const journey = document.getElementById('journey');
  const stage = screen.querySelector('#invite-form') ? 'access' : screen.querySelector('#download') && session.needs_backup ? 'recovery' : screen.querySelector('#create-form') ? 'wallet' : null;
  journey.hidden = !stage;
  const sequence = ['wallet', 'recovery', 'access'];
  for (const item of journey.querySelectorAll('li')) {
    const current = item.dataset.step === stage;
    if (current) item.setAttribute('aria-current', 'step'); else item.removeAttribute('aria-current');
    item.classList.toggle('complete', sequence.indexOf(item.dataset.step) < sequence.indexOf(stage));
    if (item.dataset.step === 'access') item.hidden = session.invite_required !== true;
  }
  const credentialForm = screen.querySelector('#create-form, #restore-form, #unlock-form');
  document.getElementById('session-state').textContent = password && !credentialForm ? 'Unlocked on this device' : session.exists ? 'Encrypted wallet · Locked' : 'Device-local wallet';
  if (screen.querySelector('#restore-form')) syncState('Recovery file required');
  else if (!password) syncState(session.exists ? 'Password required' : 'Ready to create');
  else if (stage === 'recovery') syncState('Save your recovery', 'pending');
  else if (stage === 'access') syncState('Invitation required', 'pending');
  const heading = screen.querySelector('h2');
  if (heading) { heading.tabIndex = -1; heading.focus({ preventScroll: true }); }
  if (matchMedia('(max-width: 760px)').matches) window.scrollTo(0, 0);
  screen.querySelectorAll('input[type=password]').forEach(input => {
    const wrapper = document.createElement('div'); wrapper.className = 'password-field'; input.before(wrapper); wrapper.append(input);
    const toggle = document.createElement('button'); toggle.type = 'button'; toggle.className = 'reveal'; toggle.setAttribute('aria-pressed', 'false'); toggle.setAttribute('aria-label', `Show ${input.id === 'invitation' ? 'invitation code' : input.id === 'confirm' ? 'confirm password' : 'password'}`);
    toggle.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>';
    toggle.addEventListener('click', () => { input.type = input.type === 'password' ? 'text' : 'password'; toggle.setAttribute('aria-pressed', String(input.type === 'text')); toggle.setAttribute('aria-label', `${input.type === 'text' ? 'Hide' : 'Show'} ${input.id === 'invitation' ? 'invitation code' : input.id === 'confirm' ? 'confirm password' : 'password'}`); }); wrapper.append(toggle);
  });
  screen.querySelectorAll('input,textarea').forEach(input => input.addEventListener('input', () => input.removeAttribute('aria-invalid')));
}
function on(id, event, callback) { document.getElementById(id).addEventListener(event, callback); }
function operationError(text, payment = false) {
  if (typeof text === 'string' && /^error sending request for url \(https?:\/\/[^)\s]+\)$/.test(text)) {
    return payment
      ? 'The test network connection is unavailable. Check the saved payment status before sending again.'
      : 'The test network is unavailable. Your wallet is still saved on this device. Try again when the network is available.';
  }
  return text;
}
async function api(action, extra = {}) {
  let response;
  try { response = await fetch('/api/wallet', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Wallet-Token': session.token, 'Accept': ['send','withdraw'].includes(action) ? 'application/x-ndjson' : 'application/json' }, body: JSON.stringify({ action, password, ...extra }) }); }
  catch { if (['send','withdraw'].includes(action)) session.pending = true; throw new Error('The local wallet connection is unavailable. Restart the local session and unlock your wallet to check its payment status.'); }
  if (response.headers.get('Content-Type')?.startsWith('application/x-ndjson')) return paymentStream(response);
  let body;
  try { body = await response.json(); }
  catch { if (['send','withdraw'].includes(action)) session.pending = true; throw new Error('The wallet response was interrupted. Check the saved payment status before sending again.'); }
  if (body.status) Object.assign(session, body.status);
  if (!response.ok) throw new Error(operationError(body.error || 'The wallet could not complete this operation.', ['send','withdraw'].includes(action)));
  return body.result;
}
async function paymentStream(response) {
  const labels = {
    key: 'Preparing the local proof engine…', sync: 'Verifying your finalized balance…',
    prove: 'Creating your private payment proof on this device…', upload: 'Uploading the encrypted payment and proof…',
    confirm: 'Waiting for network confirmation…', finalize: 'Payment confirmed. Waiting for finality…',
    native_packet_durable: 'Payment saved on this device. Sending the private proof…',
  };
  let terminal = null, buffered = '', total = 0;
  try {
    const reader = response.body.getReader(), decoder = new TextDecoder();
    function frame(line) {
      if (!line.trim()) return;
      const value = JSON.parse(line);
      if (value.progress && Object.hasOwn(labels, value.progress) && !terminal) {
        progressLabel = labels[value.progress]; message(progressLabel);
      } else if (Object.hasOwn(value, 'result') || Object.hasOwn(value, 'error')) {
        if (terminal) throw new Error('Duplicate wallet result');
        terminal = value;
      } else throw new Error('Invalid wallet progress');
    }
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      total += value.length;
      if (total > 65536) throw new Error('Wallet response exceeded its limit');
      buffered += decoder.decode(value, {stream:true});
      let end;
      while ((end = buffered.indexOf('\n')) !== -1) { frame(buffered.slice(0, end)); buffered = buffered.slice(end + 1); }
    }
    buffered += decoder.decode();
    if (buffered.trim()) frame(buffered);
    if (!terminal) throw new Error('Wallet result was interrupted');
  } catch {
    // A transport failure is never permission to submit the payment again.
    if (!terminal) {
      session.pending = true;
      throw new Error('Payment status is unavailable. Check the saved payment status or refresh your balance before sending again.');
    }
  }
  if (terminal.status) Object.assign(session, terminal.status);
  if (terminal.error) throw new Error(operationError(terminal.error, true));
  return terminal.result;
}
function progress(label) {
  clearInterval(progressTimer);
  progressLabel = label; progressStarted = Date.now(); message(label);
  syncState('Operation in progress');
  // Elapsed time is real; no invented percentage or completion estimate.
  progressTimer = setInterval(() => {
    if (!busy) return;
    const seconds = Math.floor((Date.now() - progressStarted) / 1000);
    if (seconds >= 5) message(`${progressLabel} ${seconds}s elapsed. Keep this tab open.`);
  }, 5000);
}
async function work(label, action, activity = true) {
  if (busy) return;
  const previousFocus = document.activeElement;
  busy = true; progress(label);
  screen.setAttribute?.('aria-busy', 'true');
  screen.querySelectorAll('button,input,textarea').forEach(el => el.disabled = true);
  try { await action(); } catch (error) { message(error.message || 'The local wallet is unavailable. Check that the local network is running.', 'error'); }
  finally { clearInterval(progressTimer); busy = false; screen.removeAttribute?.('aria-busy'); screen.querySelectorAll('button,input,textarea').forEach(el => el.disabled = false); if (session.pending || session.staging) ['send','fund','withdraw'].forEach(id => { const control = document.getElementById(id); if (control) control.disabled = true; }); applyAvailability(); settledSyncState(); if (previousFocus && screen.contains(previousFocus) && !previousFocus.disabled && document.activeElement === document.body) previousFocus.focus({preventScroll:true}); if (activity) touch(); }
}
function applyAvailability() {
  for (const id of ['send', 'withdraw']) {
    const control = document.getElementById(id);
    if (control) control.disabled = busy || !balanceVerified || session.pending || session.staging || !Number.isSafeInteger(balance) || balance < 1;
  }
  if (session.operator_sponsor_available === false) {
    const fundButton = document.getElementById('fund'); if (fundButton) fundButton.disabled = busy || !session.test_faucet_configured || session.pending || session.staging;
    const sendButton = document.getElementById('send'); if (sendButton && session.user_paid_sends !== true) sendButton.disabled = true;
    const fund = document.getElementById('fund');
    if (fund && !document.getElementById('availability-note')) {
      const note = document.createElement('p'); note.id = 'availability-note'; note.className = 'hint';
      note.textContent = (session.private_send_transport === 'native-inline-v1' ? 'Private sends pay fees from your private balance. Public withdrawals still use a funded fee account.' : 'Private sends and public withdrawals use your funded fee account.') + (session.test_faucet_configured ? ' A test-coin endpoint is configured; funding depends on the operator and grant status.' : ' This profile has no automatic test funding.'); fund.after(note);
    }
  }
}
function lock() { if (busy) return; password = ''; address = ''; balance = null; balanceVerified = false; lastVerifiedAt = null; receipt = null; publicAddress = ''; publicBalance = null; feeBalance = null; minimumPublicWithdrawal = null; grant = null; grantStarted = 0; clearTimeout(idle); welcome(); }
function touch() { clearTimeout(idle); if (password) idle = setTimeout(lock, 15 * 60 * 1000); }
document.addEventListener('pointerdown', touch); document.addEventListener('keydown', touch);

function welcome() {
  password = ''; balanceVerified = false;
  if (session.exists) {
    setScreen(`<h2>Welcome back.</h2><p class="caption">Unlock your private wallet.</p><form id="unlock-form"><label for="password">Wallet password</label><input id="password" type="password" autocomplete="current-password" required minlength="12"><button class="primary">Unlock wallet</button></form><p class="hint">Your encrypted wallet stays on this device.</p>`);
    on('unlock-form', 'submit', event => { event.preventDefault(); password = document.querySelector('#password').value; work('Unlocking your wallet and checking saved access…', async () => { const result = await api('unlock'); address = result.address; if (session.needs_backup) recovery(); else await dashboard(); }); });
    return;
  }
  setScreen(`<h2>Create your private wallet</h2><p class="caption">Choose a password, then save your recovery file.</p><form id="create-form"><label for="password">Wallet password</label><input id="password" type="password" autocomplete="new-password" required minlength="12" aria-describedby="password-hint"><p class="field-hint" id="password-hint">At least 12 characters. We cannot reset this password.</p><label for="confirm">Confirm password</label><input id="confirm" type="password" autocomplete="new-password" required minlength="12"><button class="primary">Create wallet</button></form><button class="secondary" id="restore">Restore a wallet</button><p class="hint">Your password and spending keys stay on this device.</p>`);
  on('restore', 'click', restore);
  on('create-form', 'submit', event => {
    event.preventDefault();
    const value = document.querySelector('#password').value;
    if (value !== document.querySelector('#confirm').value) return invalid(['confirm'], 'Your passwords do not match. Enter the same password in both fields.');
    password = value;
    work('Creating your encrypted wallet…', async () => { address = (await api('create')).address; recovery(); });
  });
}
function restore() {
  let paste = false;
  setScreen(`<h2>Restore your wallet</h2><p class="caption">Use your encrypted recovery file and its password.</p><form id="restore-form"><div id="file-input"><label for="recovery-file">Recovery file</label><input id="recovery-file" type="file" accept=".json,application/json" required></div><div id="paste-input" hidden><label for="recovery-text">Encrypted recovery text</label><textarea id="recovery-text" rows="5" maxlength="4096" spellcheck="false" autocomplete="off" placeholder="Paste the complete contents of your recovery file"></textarea></div><button type="button" class="text-button back" id="restore-mode">Paste recovery text instead</button><label for="password">Wallet password</label><input id="password" type="password" autocomplete="current-password" minlength="12" required><button class="primary">Restore wallet</button></form><button class="text-button back" id="back">Back</button>`);
  on('back', 'click', welcome);
  on('restore-mode', 'click', () => {
    paste = !paste;
    document.querySelector('#file-input').hidden = paste;
    document.querySelector('#paste-input').hidden = !paste;
    document.querySelector('#recovery-file').required = !paste;
    document.querySelector('#recovery-text').required = paste;
    document.querySelector('#restore-mode').textContent = paste ? 'Choose a recovery file instead' : 'Paste recovery text instead';
  });
  on('restore-form', 'submit', event => {
    event.preventDefault();
    const file = document.querySelector('#recovery-file').files[0];
    const text = document.querySelector('#recovery-text').value.trim();
    if (paste ? !text || new TextEncoder().encode(text).length > 4096 : !file || file.size > 4096) return message('Use a complete encrypted recovery file smaller than 4 KiB.', 'error');
    password = document.querySelector('#password').value;
    work('Restoring your encrypted wallet and checking saved access…', async () => {
      let backup;
      try { backup = JSON.parse(paste ? text : await file.text()); }
      catch { throw new Error('The recovery text is not valid JSON. Copy the complete encrypted recovery file and try again.'); }
      address = (await api('restore', { backup })).address;
      balance = null;
      try { await dashboard(); message(session.invite_required && !session.testnet_admitted ? 'Wallet restored. Check its invitation access to continue.' : 'Wallet restored. Your balance is verified.', 'success'); }
      catch { message('Wallet restored. Balance verification is unavailable; refresh when the local network is ready.', 'error'); }
    });
  });
}
async function downloadBackup() {
  const data = await api('backup');
  const url = URL.createObjectURL(new Blob([JSON.stringify(data.backup, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = 'zolana-encrypted-recovery.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function recovery() {
  let downloaded = false;
  const required = session.needs_backup;
  setScreen(`<h2>Make it yours to keep.</h2><p class="caption">${required ? 'Save your encrypted recovery file before adding funds.' : 'Keep an encrypted copy somewhere safe, separately from your password.'}</p><button class="primary" id="download">Download recovery file</button><button class="text-button back" id="show-backup">Save encrypted text instead</button><div id="backup-text-panel" hidden><label for="backup-text">Encrypted recovery text</label><textarea id="backup-text" rows="5" readonly spellcheck="false" autocomplete="off"></textarea><button class="secondary" id="copy-backup">Copy encrypted recovery</button><p class="hint">Save the complete text in a .json file. Restore with that file or paste its contents.</p></div>${required ? '<label class="check"><input id="saved" type="checkbox">I saved my recovery file somewhere safe, separately from my password.</label>' : ''}<button class="secondary" id="continue">${required ? 'Continue to wallet' : 'Back to wallet'}</button><p class="hint">You need both the file and your password to restore your funds. We cannot reset your password.</p>`);
  on('download', 'click', () => work('Preparing your encrypted recovery file…', async () => { await downloadBackup(); downloaded = true; message('Recovery download started. Confirm once you have saved it.'); }));
  on('show-backup', 'click', () => work('Preparing your encrypted recovery text…', async () => {
    document.querySelector('#backup-text').value = JSON.stringify((await api('backup')).backup, null, 2);
    document.querySelector('#backup-text-panel').hidden = false; downloaded = true;
    message('Save the complete encrypted text, then confirm below.');
  }));
  on('copy-backup', 'click', async () => {
    const field = document.querySelector('#backup-text');
    try { await navigator.clipboard.writeText(field.value); message('Encrypted recovery copied. Save it separately from your password.', 'success'); }
    catch { field.focus(); field.select(); message('Copy the selected encrypted text and save it separately from your password.'); }
  });
  on('continue', 'click', () => { if (required && (!downloaded || !document.querySelector('#saved').checked)) return message('Save your recovery file or encrypted text and confirm that you have saved it.', 'error'); work('Opening your wallet…', async () => { if (required) await api('ack-backup'); await dashboard(); }); });
}
function renderDashboard() {
  const fundingLabel = session.test_faucet_configured
    ? (session.invite_required ? 'Check test coin grant' : 'Request test coins')
    : (session.operator_sponsor_available ? `Add ${Number(session.faucet_amount || 100).toLocaleString()} test units` : 'Test funding unavailable');
  setScreen(`<div class="row"><h2>Your private wallet</h2><button class="text-button small" id="lock">Lock wallet</button></div><p class="balance-label">${balanceVerified ? 'Private balance' : balance === null ? 'Private balance not verified' : 'Last verified private balance'}</p><div class="balance" id="balance">${units(balance)}<small>ZOL test units</small></div><p class="balance-caption">${balanceVerified ? balance === 0 ? 'Ready to receive test units. Check your grant or share your private address.' : 'Verified against finalized payment history.' : 'Refresh your balance before making another payment.'}</p><div id="recovery-controls"></div><div class="row"><button class="primary" id="send">Send privately</button><button class="secondary" id="receive">Receive</button></div><button class="secondary" id="fund">${fundingLabel}</button><p class="hint" id="grant-status" role="status"></p><div id="receipt"></div><details class="account-details"><summary>Public account and network fees</summary><p class="hint" id="gas-balance"></p>${session.recipient_withdrawals ? '<p class="hint" id="public-balance"></p><button class="secondary" id="withdraw">Withdraw publicly</button>' : ''}<p class="hint">Public withdrawals reveal the amount and destination. Only use public accounts on this Zolana network.</p></details><div class="split row"><button class="text-button small" id="refresh">Refresh balance</button><button class="text-button small" id="backup">Recovery file</button></div>`);
  syncState(session.pending ? 'Saved payment needs attention' : session.staging ? 'Upload recovery required' : balanceVerified ? `Balance checked ${new Date(lastVerifiedAt || Date.now()).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}` : 'Balance not verified', session.pending || session.staging ? 'pending' : balanceVerified ? 'verified' : 'error');
  document.querySelector('#gas-balance').textContent = session.private_send_transport === 'native-inline-v1' ? `Private sends pay fees from your private balance. Public gas balance: ${units(feeBalance)} test units; needed only for public withdrawals.` : `Public gas balance: ${units(feeBalance)} test units. Used for fees and refundable upload rent.`;
  on('lock', 'click', lock); on('receive', 'click', receive); on('send', 'click', send);
  if (session.recipient_withdrawals) { on('withdraw', 'click', () => withdraw()); document.querySelector('#public-balance').textContent = `Withdrawal account balance: ${units(publicBalance)} test units on this chain.`; }
  on('refresh', 'click', () => work('Verifying finalized payment history…', dashboard));
  on('backup', 'click', recovery);
  on('fund', 'click', () => session.test_faucet_configured ? work(session.invite_required ? 'Checking your saved test grant…' : 'Requesting test coins…', async () => {
    grantStarted = Date.now(); grant = await api('test-coins');
    await dashboard();
  }) : payment('fund')); applyAvailability();
  if (grant) {
    document.getElementById('grant-status').textContent = grant.state === 'ready' ? 'Your one-time test grant finalized. Wallet balances are verified separately from chain history.' : grant.state === 'needs_attention' ? 'Your original grant is saved, but the faucet needs operator recovery. Checking again will not create a second grant.' : grant.state === 'funding' ? 'The operator started your original grant. It is not ready yet. We’ll check its status for a few minutes; you can safely close this wallet.' : 'Your original grant is queued. Funding depends on the operator. We’ll check its status for a few minutes; you can safely close this wallet.';
    if (session.test_faucet_configured) document.getElementById('fund').textContent = 'Check test coin grant';
  }
  scheduleGrantCheck();
  if (receipt && typeof receipt.signature === 'string' && receipt.signature) {
    const element = document.querySelector('#receipt'); element.className = 'receipt';
    const heading = document.createElement('strong'); heading.textContent = receipt.withdrawal ? 'Withdrawal finalized' : 'Payment finalized'; element.append(heading, document.createElement('br'));
    element.append(document.createTextNode(receipt.signature));
    if (receipt.withdrawal) { const destination = document.createElement('p'); destination.className = 'address'; destination.textContent = `${receipt.withdrawal.amount} public units to ${receipt.withdrawal.recipient}`; element.append(destination); }
    if (receipt.staging_account && !receipt.staging_rent_reclaimed) element.append(document.createElement('br'), document.createTextNode('Payment succeeded. Upload rent still needs recovery.'));
  }
  if (session.pending || session.staging) {
    ['fund','send','withdraw'].forEach(id => { const button = document.getElementById(id); if (button) button.disabled = true; });
    const controls = document.querySelector('#recovery-controls');
    controls.className = 'recovery-callout';
    const title = document.createElement('h3'); title.textContent = session.pending ? 'Check the saved payment first' : 'Finish upload recovery';
    const description = document.createElement('p'); description.className = 'hint'; description.textContent = session.pending ? 'A previous payment needs a status check before you send again.' : 'An interrupted upload needs cleanup before you send again.';
    const button = document.createElement('button'); button.className = 'secondary'; button.textContent = session.pending ? 'Check previous payment' : 'Recover upload rent';
    button.addEventListener('click', () => work('Checking finalized recovery state…', async () => {
      const result = await api(session.pending ? 'resolve' : 'reclaim');
      if (result.accepted) receipt = { ...result, staging_rent_reclaimed: !result.staging_recovery_required };
      else if (result.recovery_cleared && !session.staging && receipt?.staging_account && receipt.staging_account === result.staging_account) receipt = { ...receipt, staging_rent_reclaimed: true };
      await dashboard(); message(result.accepted ? 'The previous payment finalized. Recover its upload rent if prompted.' : 'Recovery step completed.', 'success');
    }));
    controls.append(title, description, button);
  }
}
function scheduleGrantCheck() {
  clearTimeout(grantPoll);
  if (!password || !session.test_faucet_configured || !grant || !['queued','funding'].includes(grant.state) || Date.now() - grantStarted > 180000) return;
  grantPoll = setTimeout(() => {
    if (!document.getElementById('grant-status') || !password) return;
    if (busy) return scheduleGrantCheck();
    work('Checking your saved test grant…', async () => {
      grant = await api('test-coins'); await dashboard();
    }, false);
  }, 8000);
}
function inviteAccess() {
  setScreen(`<h2>Join the private testnet</h2><p class="caption">Enter your invitation once. Access stays with this wallet when you restore it.</p><form id="invite-form"><label for="invitation">Invitation code</label><input id="invitation" type="password" autocomplete="off" spellcheck="false" autocapitalize="off" maxlength="60" required><button class="primary">Join testnet</button></form><p class="hint">One invitation admits one wallet. Test-coin funding depends on the operator and your grant status. ${session.private_send_transport === 'native-inline-v1' ? 'Private sends pay fees from your private balance; no public gas balance is needed.' : 'Private sends use a funded public fee account.'} Invitations can expire or be revoked.</p><p class="hint">Joining shares your receiving address with the gateway. It sees your IP address and request timing, and can link your submissions to this membership.</p><button class="secondary" id="check-access">Check existing access</button><div class="row"><button class="text-button" id="invite-receive">Receiving address</button><button class="text-button" id="invite-backup">Recovery file</button></div><button class="text-button" id="invite-lock">Lock wallet</button>`);
  on('invite-form','submit',event => {
    event.preventDefault(); const invitation=document.getElementById('invitation').value.trim();
    work('Checking your invitation…',async()=> {
      grant=await api('join',{invitation}); grantStarted=Date.now(); await dashboard();
    });
  });
  on('check-access','click',()=>work('Checking this wallet’s saved access…',async()=> {
    const result=await api('access-status');
    if (!result.admitted) { inviteAccess(); return message('This wallet has no active invitation access. Check your code or contact the test operator.','error'); }
    await dashboard();
    message(session.test_faucet_configured ? 'Access confirmed. Use Check test coin grant to see its funding status.' : 'Access confirmed. This profile has no test-coin endpoint.', 'success');
  }));
  on('invite-receive','click',receive); on('invite-backup','click',recovery); on('invite-lock','click',lock);
}
async function dashboard() {
  if (session.invite_required && !session.testnet_admitted) return inviteAccess();
  balanceVerified = false;
  syncState('Checking finalized history');
  try {
    setScreen('<h2>Verifying your balance</h2><p class="caption">Checking finalized payment history for this wallet.</p><p class="hint">Your first sync checks the full history. Later refreshes use your verified checkpoint. Network limits may briefly pause this check.</p>');
    progress('Verifying finalized payment history…');
    const result = await api('balance');
    if (!Number.isSafeInteger(result.balance) || result.balance < 0) throw new Error('The verified balance response is unavailable. Refresh before making a payment.');
    balance = result.balance; publicAddress = result.public_address || ''; publicBalance = result.public_balance ?? null; feeBalance = result.fee_balance ?? null; minimumPublicWithdrawal = result.minimum_public_withdrawal ?? null;
    balanceVerified = true; lastVerifiedAt = Date.now();
  } catch (error) { if (session.invite_required && !session.testnet_admitted) inviteAccess(); else renderDashboard(); throw error; }
  renderDashboard();
}
function receive() {
  setScreen(`<h2>Receive privately</h2><p class="caption">Share this address with someone using the same Zolana network.</p><p class="address" id="address" tabindex="0" aria-label="Your private receiving address"></p><button class="primary" id="copy">Copy receiving address</button><button class="secondary" id="back">Back to wallet</button><p class="hint">Only Zolana private payments can arrive here. This address cannot receive SOL or USDC from Solana.</p>`);
  document.querySelector('#address').textContent = address;
  on('copy', 'click', async () => { try { await navigator.clipboard.writeText(address); message('Receiving address copied.', 'success'); } catch { document.querySelector('#address').focus(); message('Select the complete address above and copy it.'); } });
  on('back', 'click', () => session.invite_required && !session.testnet_admitted ? inviteAccess() : renderDashboard());
}
function send(draft = {}) {
  if (session.pending || session.staging) return renderDashboard();
  if (!balanceVerified) { renderDashboard(); return message('Refresh your balance before starting a payment.', 'error'); }
  if (session.private_send_transport === 'native-inline-v1') return work('Checking the private payment fee…', async () => renderSend(draft, await api('fees', {payment:'send'})));
  if (draft.fee_mode === 'sponsor') return renderSend(draft, null);
  return work('Checking your fee account and upload rent…', async () => renderSend(draft, await api('fees', {payment:'send'})));
}
function renderSend(draft, quote) {
  if (session.pending || session.staging) return renderDashboard();
  const shieldedFees = session.private_send_transport === 'native-inline-v1';
  const ownFees = !shieldedFees && draft.fee_mode !== 'sponsor';
  if (shieldedFees && (quote?.fee_mode !== 'shielded' || quote.transport !== 'native-inline-v1' || !Number.isSafeInteger(quote.shielded_fee) || quote.shielded_fee < 1 || quote.shielded_fee > 100000000 || quote.maximum_shielded_fee !== quote.shielded_fee)) throw new Error('The private fee quote is unavailable. Refresh before continuing.');
  if (ownFees && quote.payment !== 'send') throw new Error('The fee quote does not match a private send. Refresh before continuing.');
  setScreen(`<h2>Send privately</h2><p class="caption">Pay a private address on this Zolana network.</p><form id="send-form"><label for="recipient">Recipient address</label><textarea id="recipient" required rows="3" maxlength="140" placeholder="npriv1…" spellcheck="false" autocapitalize="off" autocorrect="off" aria-describedby="recipient-hint"></textarea><p class="field-hint" id="recipient-hint">Ask the recipient to copy their complete private address.</p><label for="amount">Amount in ZOL test units</label><input id="amount" type="number" inputmode="numeric" min="1" step="1" required aria-describedby="amount-hint"><p class="field-hint" id="amount-hint">Private balance: ${units(balance)} test units. Fees are shown below.</p><div id="fee-details"></div><button class="primary">Review payment</button></form><button class="text-button back" id="back">Back to wallet</button>`);
  document.querySelector('#recipient').value = draft.recipient || '';
  document.querySelector('#amount').value = draft.amount || '';
  feeDetails(draft, quote, send);
  on('back', 'click', renderDashboard);
  on('send-form', 'submit', event => {
    event.preventDefault(); const recipient = document.querySelector('#recipient').value.trim(), amount = Number(document.querySelector('#amount').value);
    if (!recipient.startsWith('npriv1')) return invalid(['recipient'], 'Enter the recipient’s complete private Zolana address, beginning npriv1.');
    if (!Number.isSafeInteger(amount) || amount < 1 || amount > balance) return invalid(['amount'], 'Enter a whole amount of at least 1 test unit within your private balance.');
    if (shieldedFees) {
      if (amount + quote.shielded_fee > balance) return invalid(['amount'], `Keep ${units(quote.shielded_fee)} test units in your private balance for the payment fee.`);
      return review(recipient, amount, 'send', {fee_mode:'shielded',max_shielded_fee:quote.maximum_shielded_fee});
    }
    if (ownFees && quote.funding_shortfall) return message('Fund the fee address with public native coins, then refresh its balance. Upload rent is returned after cleanup.', 'error');
    review(recipient, amount, 'send', {fee_mode:ownFees?'user':'sponsor',max_fee_debit:ownFees?quote.maximum_gross_debit:undefined});
  });
}
function withdraw(draft = {}) {
  if (session.pending || session.staging) return renderDashboard();
  if (!balanceVerified) { renderDashboard(); return message('Refresh your balance before starting a public withdrawal.', 'error'); }
  if (draft.fee_mode === 'sponsor') return renderWithdrawal(draft, null);
  return work('Checking your fee account and upload rent…', async () => renderWithdrawal(draft, await api('fees')));
}
function renderWithdrawal(draft, quote) {
  const ownFees = draft.fee_mode !== 'sponsor';
  if (session.pending || session.staging) return renderDashboard();
  if (ownFees && quote.payment !== 'withdraw') throw new Error('The fee quote does not match a withdrawal. Refresh before continuing.');
  setScreen(`<h2>Withdraw publicly</h2><p class="caption">Move private funds to a public account on this chain.</p><form id="withdraw-form"><label for="recipient">Public destination address</label><textarea id="recipient" required rows="2" maxlength="44" spellcheck="false" autocapitalize="off" autocorrect="off"></textarea><p class="hint">The default account is controlled by your recovery seed. This sends this chain's native coin, not SOL on Solana.</p><label for="amount">Amount in ZOL test units</label><input id="amount" type="number" inputmode="numeric" min="1" step="1" required aria-describedby="withdraw-minimum"><p class="hint" id="withdraw-minimum"></p><div id="fee-details"></div><button class="primary">Review withdrawal</button></form><button class="text-button back" id="back">Back to wallet</button>`);
  document.querySelector('#recipient').value = draft.recipient || publicAddress;
  document.querySelector('#amount').value = draft.amount || '';
  document.querySelector('#withdraw-minimum').textContent = (minimumPublicWithdrawal > 1 ? `Your public account needs at least ${units(minimumPublicWithdrawal)} test units for its first withdrawal. ` : 'Your destination receives the full withdrawal amount. ') + (ownFees ? 'You pay fees and rent separately.' : 'The sponsor pays fees and rent.');
  feeDetails(draft, quote, withdraw);
  on('back', 'click', renderDashboard);
  on('withdraw-form', 'submit', event => {
    event.preventDefault();
    const recipient = document.querySelector('#recipient').value.trim(), amount = Number(document.querySelector('#amount').value);
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(recipient)) return invalid(['recipient'], 'Enter a complete public account address on this Zolana network.');
    if (!Number.isSafeInteger(amount) || amount < 1 || amount > balance) return invalid(['amount'], 'Enter a whole withdrawal amount within your private balance.');
    if (recipient === publicAddress && amount < minimumPublicWithdrawal) return invalid(['amount'], `Withdraw at least ${units(minimumPublicWithdrawal)} test units to create this public account.`);
    if (ownFees && quote.funding_shortfall) return message('Fund the fee address with public native coins, then refresh its balance. Upload rent is returned after cleanup.', 'error');
    review(recipient, amount, 'withdraw', {fee_mode:ownFees?'user':'sponsor',max_fee_debit:ownFees?quote.maximum_gross_debit:undefined});
  });
}
function feeDetails(draft, quote, rerender) {
  const ownFees = draft.fee_mode !== 'sponsor';
  const fees = document.querySelector('#fee-details');
  function breakdown(rows) {
    const card = document.createElement('div'); card.className = 'fee-breakdown';
    const list = document.createElement('dl');
    rows.forEach(([label, value, total]) => {
      const row = document.createElement('div'); if (total) row.className = 'fee-total';
      const term = document.createElement('dt'); term.textContent = label;
      const description = document.createElement('dd'); description.textContent = `${units(value)} test units`;
      row.append(term, description); list.append(row);
    });
    card.append(list); fees.append(card); return card;
  }
  if (quote?.fee_mode === 'shielded' && session.private_send_transport === 'native-inline-v1' && rerender === send) {
    const card = breakdown([['Private payment fee', quote.shielded_fee, true]]);
    const details = document.createElement('p'); details.className = 'hint'; details.id = 'fee-quote';
    details.textContent = 'Deducted from your private balance, in addition to the amount you send. You need no public gas balance. The relay account and fee remain public.';
    card.append(details);
    const refresh = document.createElement('button'); refresh.type = 'button'; refresh.className = 'text-button back'; refresh.textContent = 'Refresh private fee';
    refresh.onclick = () => rerender({recipient:document.querySelector('#recipient').value,amount:document.querySelector('#amount').value,fee_mode:'shielded'});
    fees.append(refresh); return;
  }
  if (ownFees) {
    const card = breakdown([
      ['Fee account balance', quote.public_balance],
      ['Refundable upload rent', quote.refundable_staging_rent],
      ['Permanent nullifier rent', quote.permanent_nullifier_rent],
      ['Estimated transaction fees', quote.transaction_fees],
      ['Upload repair allowance, if needed', quote.upload_repair_reserve || 0],
      ['Maximum authorized debit', quote.maximum_gross_debit, true],
    ]);
    const address = document.createElement('p'); address.className = 'address'; address.id = 'fee-address'; address.textContent = quote.fee_address; address.tabIndex = 0; address.setAttribute('aria-label', 'Public fee account address');
    const details = document.createElement('p'); details.className = 'hint'; details.id = 'fee-quote';
    details.textContent = `Fees come from the public account controlled by your recovery seed. Upload rent returns after cleanup. Keep ${units(quote.minimum_remaining_balance)} test units in the account. ${quote.funding_shortfall ? `Add at least ${units(quote.funding_shortfall)} public test units on this Zolana network before continuing.` : 'The fee account is funded.'}`;
    card.append(details); fees.append(address);
    const refresh = document.createElement('button'); refresh.type = 'button'; refresh.className = 'text-button back'; refresh.textContent = 'Refresh fee balance';
    refresh.onclick = () => rerender({recipient:document.querySelector('#recipient').value,amount:document.querySelector('#amount').value,fee_mode:'user'}); fees.append(refresh);
  }
  if (session.operator_sponsor_available) {
    const mode = document.createElement('button'); mode.type = 'button'; mode.className = 'secondary'; mode.textContent = ownFees ? 'Use test sponsor' : 'Pay my own fees';
    mode.onclick = () => rerender({recipient:document.querySelector('#recipient').value,amount:document.querySelector('#amount').value,fee_mode:ownFees?'sponsor':'user'}); fees.append(mode);
    if (!ownFees) { const note = document.createElement('p'); note.className = 'hint'; note.textContent = 'The selected test sponsor pays network fees and rent. The operator can observe this request.'; fees.append(note); }
  }
}
function review(recipient, amount, action = 'send', fees = {}) {
  const withdrawing = action === 'withdraw';
  setScreen(`<h2>${withdrawing ? 'Review public withdrawal' : 'Review private payment'}</h2><p class="balance-label">${withdrawing ? 'Leaving your private balance' : 'Recipient receives'}</p><div class="balance" id="review-amount"></div><p class="balance-caption" id="review-total"></p><p class="hint">${withdrawing ? 'Public destination' : 'Private receiving address'}</p><p class="address" id="review-address"></p><div class="review-privacy${withdrawing ? ' public' : ''}"><strong>${withdrawing ? 'This withdrawal becomes public' : 'Private on the public ledger'}</strong><p class="hint" id="review-fees"></p></div><button class="primary" id="confirm-send">${withdrawing ? 'Withdraw publicly' : 'Send payment'}</button><button class="secondary" id="back">${withdrawing ? 'Edit withdrawal' : 'Edit payment'}</button>`);
  const feeDescription = fees.fee_mode === 'shielded' ? `You authorize up to ${units(fees.max_shielded_fee)} test units in fees from your private balance. You need no public gas balance for this send. The relay account and fee remain public.` : fees.fee_mode === 'user' ? `You authorize up to ${units(fees.max_fee_debit)} test units of gross debit from your seed-controlled fee account, including refundable upload rent. Your public fee account and transaction timing remain visible.` : 'The selected test sponsor pays fees and rent.';
  document.querySelector('#review-fees').textContent = (withdrawing ? 'The amount and destination become public on this chain. ' : 'The payment amount and private receiving address stay hidden on the public ledger. ') + feeDescription + (session.invite_required ? ' The gateway can link this request to your testnet membership.' : '');
  const amountElement = document.querySelector('#review-amount'); amountElement.textContent = units(amount);
  const denomination = document.createElement('small'); denomination.textContent = 'ZOL test units'; amountElement.append(denomination);
  document.querySelector('#review-total').textContent = fees.fee_mode === 'shielded' ? `Maximum private debit, including fee: ${units(amount + fees.max_shielded_fee)} test units.` : fees.fee_mode === 'user' ? `Public fee account: up to ${units(fees.max_fee_debit)} additional test units.` : 'Network fees are paid by the selected test sponsor.';
  document.querySelector('#review-address').textContent = recipient;
  on('back', 'click', () => withdrawing ? withdraw({ recipient, amount, ...fees }) : send({ recipient, amount, ...fees })); on('confirm-send', 'click', () => payment(action, { recipient, amount, ...fees }));
}

async function payment(action, extra = {}) {
  await work('Preparing your private payment…', async () => {
    balanceVerified = false;
    try { receipt = await api(action, extra); }
    catch (error) { renderDashboard(); throw error; }
    if (receipt?.accepted === false) {
      await dashboard(); return message('The saved payment did not execute. Your balance is verified; you can review a new payment.');
    }
    if (extra.fee_mode === 'shielded' && (receipt?.accepted !== true || receipt.encrypted_checkpoint_durable !== true)) {
      session.pending = true; renderDashboard(); throw new Error('The payment outcome is incomplete. Check the saved payment before sending again.');
    }
    // An accepted receipt stays a success even if the following balance sync fails.
    renderDashboard(); message('Payment finalized. Refreshing your balance…', 'success');
    try { await dashboard(); message('Payment finalized. Your balance is up to date.', 'success'); }
    catch { message('Payment finalized. Balance refresh is unavailable; refresh it before another payment.', 'success'); }
  });
}
document.querySelector('#privacy').addEventListener('click', () => document.querySelector('#privacy-dialog').showModal());
document.querySelector('#close-privacy').addEventListener('click', () => document.querySelector('#privacy-dialog').close());
try {
  session = await (await fetch('/api/session')).json();
  if (!session || typeof session.token !== 'string' || !session.token) throw new Error('The wallet session could not be verified.');
  document.querySelector('#network-label').textContent = session.network || 'ZOL test network';
  if (Number.isInteger(session.previous_wallet_port) && session.previous_wallet_port >= 1024 && session.previous_wallet_port <= 65535) {
    const previous = document.querySelector('#previous-wallet'); previous.href = `http://127.0.0.1:${session.previous_wallet_port}/`; previous.hidden = false;
  }
  welcome();
}
catch {
  setScreen('<h2>Local wallet unavailable</h2><p class="caption">The wallet session on this device could not be reached. Your encrypted wallet is still saved.</p><button class="primary" id="retry-session">Try local session again</button><p class="hint">If this continues, reopen your installed wallet. Keep your existing wallet data and recovery file.</p>');
  syncState('Local session unavailable', 'error');
  on('retry-session', 'click', () => location.reload());
  message('The local wallet connection failed. No payment was sent.', 'error');
}
