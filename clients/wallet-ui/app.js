const screen = document.querySelector('#screen');
const notice = document.querySelector('#notice');
let progressTimer, progressLabel = '', progressStarted = 0;
let session = {}, password = '', address = '', balance = null, receipt = null, publicAddress = '', publicBalance = null, feeBalance = null, minimumPublicWithdrawal = null, busy = false, idle, grant = null, grantPoll, grantStarted = 0;

function message(text = '', kind = '') {
  notice.textContent = text; notice.className = kind;
  if (kind === 'error') notice.scrollIntoView({ block: 'nearest' });
}
function setScreen(html) {
  clearTimeout(grantPoll);
  screen.innerHTML = html; message();
  const heading = screen.querySelector('h2');
  if (heading) { heading.tabIndex = -1; heading.focus({ preventScroll: true }); }
  if (matchMedia('(max-width: 760px)').matches) window.scrollTo(0, 0);
  screen.querySelectorAll('input[type=password]').forEach(input => {
    const wrapper = document.createElement('div'); wrapper.className = 'password-field'; input.before(wrapper); wrapper.append(input);
    const toggle = document.createElement('button'); toggle.type = 'button'; toggle.className = 'reveal'; toggle.setAttribute('aria-label', `Show ${input.id === 'invitation' ? 'invitation code' : input.id === 'confirm' ? 'confirm password' : 'password'}`);
    toggle.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>';
    toggle.addEventListener('click', () => { input.type = input.type === 'password' ? 'text' : 'password'; toggle.setAttribute('aria-pressed', String(input.type === 'text')); toggle.setAttribute('aria-label', `${input.type === 'text' ? 'Hide' : 'Show'} ${input.id === 'invitation' ? 'invitation code' : input.id === 'confirm' ? 'confirm password' : 'password'}`); }); wrapper.append(toggle);
  });
}
function on(id, event, callback) { document.getElementById(id).addEventListener(event, callback); }
async function api(action, extra = {}) {
  let response;
  try { response = await fetch('/api/wallet', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Wallet-Token': session.token }, body: JSON.stringify({ action, password, ...extra }) }); }
  catch { throw new Error('The local wallet connection is unavailable. Restart the local session and unlock your wallet to check its payment status.'); }
  const body = await response.json();
  if (body.status) Object.assign(session, body.status);
  if (!response.ok) throw new Error(body.error || 'The wallet could not complete this operation.');
  return body.result;
}
function progress(label) {
  clearInterval(progressTimer);
  progressLabel = label; progressStarted = Date.now(); message(label);
  // Elapsed time is real; no invented percentage or completion estimate.
  progressTimer = setInterval(() => {
    if (!busy) return;
    const seconds = Math.floor((Date.now() - progressStarted) / 1000);
    if (seconds >= 5) message(`${progressLabel} ${seconds}s elapsed. Keep this tab open.`);
  }, 5000);
}
async function work(label, action, activity = true) {
  if (busy) return;
  busy = true; progress(label);
  screen.querySelectorAll('button,input,textarea').forEach(el => el.disabled = true);
  try { await action(); } catch (error) { message(error.message || 'The local wallet is unavailable. Check that the local network is running.', 'error'); }
  finally { clearInterval(progressTimer); busy = false; screen.querySelectorAll('button,input,textarea').forEach(el => el.disabled = false); if (session.pending || session.staging) ['send','fund','withdraw'].forEach(id => { const control = document.getElementById(id); if (control) control.disabled = true; }); applyAvailability(); if (activity) touch(); }
}
function applyAvailability() {
  if (session.operator_sponsor_available === false) {
    const fundButton = document.getElementById('fund'); if (fundButton) fundButton.disabled = !session.test_faucet_available || session.pending || session.staging;
    const sendButton = document.getElementById('send'); if (sendButton && session.user_paid_sends !== true) sendButton.disabled = true;
    const fund = document.getElementById('fund');
    if (fund && !document.getElementById('availability-note')) {
      const note = document.createElement('p'); note.id = 'availability-note'; note.className = 'hint';
      note.textContent = session.test_faucet_available ? 'One free test grant includes private coins and public gas for your own sends. Test units have no monetary value. The faucet sees your receiving and fee addresses together.' : 'Send privately or withdraw using your funded fee account. This profile has no automatic test funding.'; fund.after(note);
    }
  }
}
function lock() { if (busy) return; password = ''; address = ''; balance = null; receipt = null; publicAddress = ''; publicBalance = null; feeBalance = null; minimumPublicWithdrawal = null; grant = null; grantStarted = 0; welcome(); }
function touch() { clearTimeout(idle); if (password) idle = setTimeout(lock, 15 * 60 * 1000); }
document.addEventListener('pointerdown', touch); document.addEventListener('keydown', touch);

function welcome() {
  if (session.exists) {
    setScreen(`<h2>Welcome back.</h2><p class="caption">Unlock your private wallet.</p><form id="unlock-form"><label for="password">Wallet password</label><input id="password" type="password" autocomplete="current-password" required minlength="12"><button class="primary">Unlock wallet</button></form><p class="hint">Your encrypted wallet stays on this device.</p>`);
    on('unlock-form', 'submit', event => { event.preventDefault(); password = document.querySelector('#password').value; work('Unlocking your wallet and checking saved access…', async () => { const result = await api('unlock'); address = result.address; if (session.needs_backup) recovery(); else await dashboard(); }); });
    return;
  }
  setScreen(`<h2>Create your private wallet</h2><p class="caption">Keep your recovery file. Only you can unlock it.</p><form id="create-form"><label for="password">Wallet password</label><input id="password" type="password" autocomplete="new-password" required minlength="12"><label for="confirm">Confirm password</label><input id="confirm" type="password" autocomplete="new-password" required minlength="12"><button class="primary">Create wallet</button></form><button class="secondary" id="restore">Restore a wallet</button><p class="hint">Your password stays on this device.</p>`);
  on('restore', 'click', restore);
  on('create-form', 'submit', event => {
    event.preventDefault();
    const value = document.querySelector('#password').value;
    if (value !== document.querySelector('#confirm').value) return message('Your passwords do not match.', 'error');
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
  const link = document.createElement('a'); link.href = url; link.download = 'encrypted-recovery.json'; link.click();
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
  setScreen(`<div class="row"><h2>Your private wallet</h2><button class="text-button small" id="lock">Lock</button></div><div class="balance" id="balance">${balance === null ? '—' : balance}<small> test units</small></div><p class="hint">Verified from finalized payment history.</p><p class="hint" id="gas-balance"></p><div class="row"><button class="primary" id="send">Send</button><button class="secondary" id="receive">Receive</button></div><button class="secondary" id="fund">${session.test_faucet_available ? 'Get test coins + gas' : `Add ${Number(session.faucet_amount || 100).toLocaleString()} test units`}</button>${session.recipient_withdrawals ? '<button class="secondary" id="withdraw">Withdraw publicly</button><p class="hint" id="public-balance"></p>' : ''}<p class="hint small">Withdrawals can use your own funded fee account. Solana funding is coming later.</p><p class="hint" id="grant-status" role="status"></p><div id="receipt"></div><div class="split row"><button class="text-button small" id="refresh">Refresh balance</button><button class="text-button small" id="backup">Recovery file</button></div><div id="recovery-controls"></div>`);
  document.querySelector('#gas-balance').textContent = `Public gas balance: ${feeBalance === null ? '—' : feeBalance} test units. Used for fees and refundable upload rent.`;
  on('lock', 'click', lock); on('receive', 'click', receive); on('send', 'click', send);
  if (session.recipient_withdrawals) { on('withdraw', 'click', () => withdraw()); document.querySelector('#public-balance').textContent = `Withdrawal account: ${publicBalance === null ? '—' : publicBalance} test units on this chain.`; }
  on('refresh', 'click', () => work('Verifying finalized payment history…', dashboard));
  on('backup', 'click', recovery);
  on('fund', 'click', () => session.test_faucet_available ? work('Requesting your test coins and gas…', async () => {
    grantStarted = Date.now(); grant = await api('test-coins');
    await dashboard();
  }) : payment('fund')); applyAvailability();
  if (grant) {
    document.getElementById('grant-status').textContent = grant.state === 'ready' ? 'Your one-time test grant finalized. Wallet balances are verified separately from chain history.' : grant.state === 'needs_attention' ? 'Your original grant is saved, but the faucet needs operator recovery. Checking again will not create a second grant.' : 'Your original grant is saved. Gas and private coins are being finalized. We’ll check automatically for a few minutes. Closing this wallet is safe; check the same grant when you return.';
    if (session.test_faucet_available) document.getElementById('fund').textContent = grant.state === 'ready' ? 'Check test grant' : 'Check coins + gas';
  }
  scheduleGrantCheck();
  if (receipt) {
    const element = document.querySelector('#receipt'); element.className = 'receipt';
    const heading = document.createElement('strong'); heading.textContent = receipt.withdrawal ? 'Withdrawal finalized' : 'Payment finalized'; element.append(heading, document.createElement('br'));
    element.append(document.createTextNode(receipt.signature));
    if (receipt.withdrawal) { const destination = document.createElement('p'); destination.className = 'address'; destination.textContent = `${receipt.withdrawal.amount} public units to ${receipt.withdrawal.recipient}`; element.append(destination); }
    if (!receipt.staging_rent_reclaimed) element.append(document.createElement('br'), document.createTextNode('Payment succeeded. Upload rent still needs recovery.'));
  }
  if (session.pending || session.staging) {
    ['fund','send','withdraw'].forEach(id => { const button = document.getElementById(id); if (button) button.disabled = true; });
    const controls = document.querySelector('#recovery-controls');
    const description = document.createElement('p'); description.className = 'hint'; description.textContent = session.pending ? 'A previous payment needs a status check before you send again.' : 'An interrupted upload needs cleanup before you send again.';
    const button = document.createElement('button'); button.className = 'secondary'; button.textContent = session.pending ? 'Check previous payment' : 'Recover upload rent';
    button.addEventListener('click', () => work('Checking finalized recovery state…', async () => {
      const result = await api(session.pending ? 'resolve' : 'reclaim');
      if (result.accepted) receipt = { ...result, staging_rent_reclaimed: !result.staging_recovery_required };
      else if (result.recovery_cleared && !session.staging && receipt?.staging_account === result.staging_account) receipt = { ...receipt, staging_rent_reclaimed: true };
      await dashboard(); message(result.accepted ? 'The previous payment finalized. Recover its upload rent if prompted.' : 'Recovery step completed.', 'success');
    }));
    controls.append(description, button);
  }
}
function scheduleGrantCheck() {
  clearTimeout(grantPoll);
  if (!password || !session.test_faucet_available || !grant || !['queued','funding'].includes(grant.state) || Date.now() - grantStarted > 180000) return;
  grantPoll = setTimeout(() => {
    if (!document.getElementById('grant-status') || !password) return;
    if (busy) return scheduleGrantCheck();
    work('Checking your saved test grant…', async () => {
      grant = await api('test-coins'); await dashboard();
    }, false);
  }, 8000);
}
function inviteAccess() {
  setScreen(`<h2>Join the private testnet</h2><p class="caption">Enter your invitation once. Access stays with this wallet when you restore it.</p><form id="invite-form"><label for="invitation">Invitation code</label><input id="invitation" type="password" autocomplete="off" spellcheck="false" autocapitalize="off" maxlength="60" required><button class="primary">Join testnet + get test coins</button></form><p class="hint">One invitation admits one wallet and includes private test coins plus public gas. Test units have no monetary value. Invitations can expire or be revoked.</p><button class="secondary" id="check-access">Check existing access</button><div class="row"><button class="text-button" id="invite-receive">Receiving address</button><button class="text-button" id="invite-backup">Recovery file</button></div><button class="text-button" id="invite-lock">Lock wallet</button>`);
  on('invite-form','submit',event => {
    event.preventDefault(); const invitation=document.getElementById('invitation').value.trim();
    work('Checking your invitation…',async()=> {
      grant=await api('join',{invitation}); grantStarted=Date.now(); await dashboard();
    });
  });
  on('check-access','click',()=>work('Checking this wallet’s saved access…',async()=> {
    const result=await api('access-status');
    if (!result.admitted) { inviteAccess(); return message('This wallet has no active invitation access. Check your code or contact the test operator.','error'); }
    progress('Access confirmed. Checking your existing test grant…');
    grant=await api('test-coins'); grantStarted=Date.now(); await dashboard();
  }));
  on('invite-receive','click',receive); on('invite-backup','click',recovery); on('invite-lock','click',lock);
}
async function dashboard() {
  if (session.invite_required && !session.testnet_admitted) return inviteAccess();
  try {
    progress('Verifying finalized payment history… Your first sync checks the full history; later refreshes use your verified checkpoint.');
    const result = await api('balance'); balance = result.balance; publicAddress = result.public_address || ''; publicBalance = result.public_balance ?? null; feeBalance = result.fee_balance ?? null; minimumPublicWithdrawal = result.minimum_public_withdrawal ?? null;
  } catch (error) { if (session.invite_required && !session.testnet_admitted) inviteAccess(); else renderDashboard(); throw error; }
  renderDashboard();
}
function receive() {
  setScreen(`<h2>Receive privately</h2><p class="caption">Share this address with someone using this local network.</p><p class="address" id="address"></p><button class="primary" id="copy">Copy receiving address</button><button class="secondary" id="back">Back to wallet</button><p class="hint">This is a private address for this chain. It cannot receive SOL or USDC from Solana.</p>`);
  document.querySelector('#address').textContent = address;
  on('copy', 'click', async () => { try { await navigator.clipboard.writeText(address); message('Receiving address copied.', 'success'); } catch { message('Select the address above and copy it.'); } });
  on('back', 'click', () => session.invite_required && !session.testnet_admitted ? inviteAccess() : renderDashboard());
}
function send(draft = {}) {
  if (session.pending || session.staging) return renderDashboard();
  if (draft.fee_mode === 'sponsor') return renderSend(draft, null);
  return work('Checking your fee account and upload rent…', async () => renderSend(draft, await api('fees', {payment:'send'})));
}
function renderSend(draft, quote) {
  if (session.pending || session.staging) return renderDashboard();
  const ownFees = draft.fee_mode !== 'sponsor';
  if (ownFees && quote.payment !== 'send') throw new Error('The fee quote does not match a private send. Refresh before continuing.');
  setScreen(`<h2>Send privately</h2><p class="caption">Pay a private address on this network.</p><form id="send-form"><label for="recipient">Recipient address</label><textarea id="recipient" required rows="3" maxlength="140" placeholder="npriv1…" spellcheck="false" autocapitalize="off" autocorrect="off"></textarea><label for="amount">Amount in test units</label><input id="amount" type="number" inputmode="numeric" min="1" step="1" required><div id="fee-details"></div><button class="primary">Review payment</button></form><button class="text-button back" id="back">Back to wallet</button>`);
  document.querySelector('#recipient').value = draft.recipient || '';
  document.querySelector('#amount').value = draft.amount || '';
  feeDetails(draft, quote, send);
  on('back', 'click', renderDashboard);
  on('send-form', 'submit', event => {
    event.preventDefault(); const recipient = document.querySelector('#recipient').value.trim(), amount = Number(document.querySelector('#amount').value);
    if (!recipient.startsWith('npriv1') || !Number.isSafeInteger(amount) || amount < 1 || amount > balance) return message('Enter a private receiving address and an amount within your balance.', 'error');
    if (ownFees && quote.funding_shortfall) return message('Fund the fee address with public native coins, then refresh its balance. Upload rent is returned after cleanup.', 'error');
    review(recipient, amount, 'send', {fee_mode:ownFees?'user':'sponsor',max_fee_debit:ownFees?quote.maximum_gross_debit:undefined});
  });
}
function withdraw(draft = {}) {
  if (session.pending || session.staging) return renderDashboard();
  if (draft.fee_mode === 'sponsor') return renderWithdrawal(draft, null);
  return work('Checking your fee account and upload rent…', async () => renderWithdrawal(draft, await api('fees')));
}
function renderWithdrawal(draft, quote) {
  const ownFees = draft.fee_mode !== 'sponsor';
  if (session.pending || session.staging) return renderDashboard();
  if (ownFees && quote.payment !== 'withdraw') throw new Error('The fee quote does not match a withdrawal. Refresh before continuing.');
  setScreen(`<h2>Withdraw publicly</h2><p class="caption">Move private funds to a public account on this chain.</p><form id="withdraw-form"><label for="recipient">Public destination address</label><textarea id="recipient" required rows="2" maxlength="44" spellcheck="false" autocapitalize="off" autocorrect="off"></textarea><p class="hint">The default account is controlled by your recovery seed. This sends this chain's native coin, not SOL on Solana.</p><label for="amount">Amount in test units</label><input id="amount" type="number" inputmode="numeric" min="1" step="1" required><p class="hint" id="withdraw-minimum"></p><div id="fee-details"></div><button class="primary">Review withdrawal</button></form><button class="text-button back" id="back">Back to wallet</button>`);
  document.querySelector('#recipient').value = draft.recipient || publicAddress;
  document.querySelector('#amount').value = draft.amount || '';
  document.querySelector('#withdraw-minimum').textContent = (minimumPublicWithdrawal > 1 ? `Your public account needs at least ${minimumPublicWithdrawal} units for its first withdrawal. ` : 'Your destination receives the full withdrawal amount. ') + (ownFees ? 'You pay fees and rent separately.' : 'The sponsor pays fees and rent.');
  feeDetails(draft, quote, withdraw);
  on('back', 'click', renderDashboard);
  on('withdraw-form', 'submit', event => {
    event.preventDefault();
    const recipient = document.querySelector('#recipient').value.trim(), amount = Number(document.querySelector('#amount').value);
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(recipient) || !Number.isSafeInteger(amount) || amount < 1 || amount > balance) return message('Enter a public address and a whole amount within your private balance.', 'error');
    if (recipient === publicAddress && amount < minimumPublicWithdrawal) return message(`Withdraw at least ${minimumPublicWithdrawal} units to create this public account.`, 'error');
    if (ownFees && quote.funding_shortfall) return message('Fund the fee address with public native coins, then refresh its balance. Upload rent is returned after cleanup.', 'error');
    review(recipient, amount, 'withdraw', {fee_mode:ownFees?'user':'sponsor',max_fee_debit:ownFees?quote.maximum_gross_debit:undefined});
  });
}
function feeDetails(draft, quote, rerender) {
  const ownFees = draft.fee_mode !== 'sponsor';
  const fees = document.querySelector('#fee-details');
  if (ownFees) {
    const address = document.createElement('p'); address.className = 'address'; address.id = 'fee-address'; address.textContent = quote.fee_address;
    const details = document.createElement('p'); details.className = 'hint'; details.id = 'fee-quote';
    details.textContent = `You pay fees from this seed-controlled fee account. Balance: ${quote.public_balance}. Refundable upload rent: ${quote.refundable_staging_rent}. Permanent nullifier rent: ${quote.permanent_nullifier_rent}. Estimated transaction fees: ${quote.transaction_fees}. Maximum gross debit authorized: ${quote.maximum_gross_debit}. Keep ${quote.minimum_remaining_balance} units in the account. ${quote.funding_shortfall ? `Fund at least ${quote.funding_shortfall} more native units on this chain before continuing.` : 'The fee account is funded.'}`;
    fees.append(details, address);
    const refresh = document.createElement('button'); refresh.type = 'button'; refresh.className = 'secondary'; refresh.textContent = 'Refresh fee balance';
    refresh.onclick = () => rerender({recipient:document.querySelector('#recipient').value,amount:document.querySelector('#amount').value,fee_mode:'user'}); fees.append(refresh);
  }
  if (session.operator_sponsor_available) {
    const mode = document.createElement('button'); mode.type = 'button'; mode.className = 'secondary'; mode.textContent = ownFees ? 'Use test sponsor' : 'Pay my own fees';
    mode.onclick = () => rerender({recipient:document.querySelector('#recipient').value,amount:document.querySelector('#amount').value,fee_mode:ownFees?'sponsor':'user'}); fees.append(mode);
  }
}
function review(recipient, amount, action = 'send', fees = {}) {
  const withdrawing = action === 'withdraw';
  setScreen(`<h2>${withdrawing ? 'Review public withdrawal' : 'Review payment'}</h2><div class="balance" id="review-amount"></div><p class="hint">To</p><p class="address" id="review-address"></p><p class="hint" id="review-fees"></p><button class="primary" id="confirm-send">${withdrawing ? 'Withdraw publicly' : 'Send payment'}</button><button class="secondary" id="back">${withdrawing ? 'Edit withdrawal' : 'Edit payment'}</button>`);
  const feeDescription = fees.fee_mode === 'user' ? `You authorize up to ${fees.max_fee_debit} units of gross debit from your seed-controlled fee account, including refundable upload rent. No operator sponsor is used. Your public fee account and transaction timing remain visible.` : 'The selected test sponsor pays fees and rent.';
  document.querySelector('#review-fees').textContent = (withdrawing ? 'The amount and destination become public on this chain. ' : 'The payment amount and recipient stay shielded. ') + feeDescription;
  document.querySelector('#review-amount').textContent = `${amount} test units`; document.querySelector('#review-address').textContent = recipient;
  on('back', 'click', () => withdrawing ? withdraw({ recipient, amount, ...fees }) : send({ recipient, amount, ...fees })); on('confirm-send', 'click', () => payment(action, { recipient, amount, ...fees }));
}

async function payment(action, extra = {}) {
  await work('Preparing your proof, uploading, and waiting for finalization. Keep this tab open…', async () => {
    try { receipt = await api(action, extra); }
    catch (error) { renderDashboard(); throw error; }
    // An accepted receipt stays a success even if the following balance sync fails.
    renderDashboard(); message('Payment finalized. Refreshing your balance…', 'success');
    try { await dashboard(); message('Payment finalized. Your balance is up to date.', 'success'); }
    catch { message('Payment finalized. Balance refresh is unavailable; refresh it before another payment.', 'success'); }
  });
}
document.querySelector('#privacy').addEventListener('click', () => document.querySelector('#privacy-dialog').showModal());
document.querySelector('#close-privacy').addEventListener('click', () => document.querySelector('#privacy-dialog').close());
try { session = await (await fetch('/api/session')).json(); document.querySelector('#network-label').textContent = session.network; welcome(); }
catch { message('The local wallet is unavailable. Restart the local wallet session.', 'error'); }
