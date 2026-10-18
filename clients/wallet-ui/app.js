const screen = document.querySelector('#screen');
const notice = document.querySelector('#notice');
let session = {}, password = '', address = '', balance = null, receipt = null, publicAddress = '', publicBalance = null, minimumPublicWithdrawal = null, busy = false, idle;

function message(text = '', kind = '') {
  notice.textContent = text; notice.className = kind;
  if (kind === 'error') notice.scrollIntoView({ block: 'nearest' });
}
function setScreen(html) {
  screen.innerHTML = html; message();
  const heading = screen.querySelector('h2');
  if (heading) { heading.tabIndex = -1; heading.focus({ preventScroll: true }); }
  if (matchMedia('(max-width: 760px)').matches) window.scrollTo(0, 0);
  screen.querySelectorAll('input[type=password]').forEach(input => {
    const wrapper = document.createElement('div'); wrapper.className = 'password-field'; input.before(wrapper); wrapper.append(input);
    const toggle = document.createElement('button'); toggle.type = 'button'; toggle.className = 'reveal'; toggle.setAttribute('aria-label', `Show ${input.id === 'confirm' ? 'confirm password' : 'password'}`);
    toggle.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>';
    toggle.addEventListener('click', () => { input.type = input.type === 'password' ? 'text' : 'password'; toggle.setAttribute('aria-pressed', String(input.type === 'text')); toggle.setAttribute('aria-label', `${input.type === 'text' ? 'Hide' : 'Show'} ${input.id === 'confirm' ? 'confirm password' : 'password'}`); }); wrapper.append(toggle);
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
async function work(label, action) {
  if (busy) return;
  busy = true; message(label);
  screen.querySelectorAll('button,input,textarea').forEach(el => el.disabled = true);
  try { await action(); } catch (error) { message(error.message || 'The local wallet is unavailable. Check that the local network is running.', 'error'); }
  finally { busy = false; screen.querySelectorAll('button,input,textarea').forEach(el => el.disabled = false); if (session.pending || session.staging) ['send','fund','withdraw'].forEach(id => { const control = document.getElementById(id); if (control) control.disabled = true; }); touch(); }
}
function lock() { if (busy) return; password = ''; address = ''; balance = null; receipt = null; publicAddress = ''; publicBalance = null; minimumPublicWithdrawal = null; welcome(); }
function touch() { clearTimeout(idle); if (password) idle = setTimeout(lock, 15 * 60 * 1000); }
document.addEventListener('pointerdown', touch); document.addEventListener('keydown', touch);

function welcome() {
  if (session.exists) {
    setScreen(`<h2>Welcome back.</h2><p class="caption">Unlock your private wallet.</p><form id="unlock-form"><label for="password">Wallet password</label><input id="password" type="password" autocomplete="current-password" required minlength="12"><button class="primary">Unlock wallet</button></form><p class="hint">Your encrypted wallet stays on this device.</p>`);
    on('unlock-form', 'submit', event => { event.preventDefault(); password = document.querySelector('#password').value; work('Unlocking your wallet…', async () => { const result = await api('unlock'); address = result.address; if (session.needs_backup) recovery(); else await dashboard(); }); });
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
    work('Restoring and verifying your wallet…', async () => {
      let backup;
      try { backup = JSON.parse(paste ? text : await file.text()); }
      catch { throw new Error('The recovery text is not valid JSON. Copy the complete encrypted recovery file and try again.'); }
      address = (await api('restore', { backup })).address;
      balance = null; renderDashboard();
      try { await dashboard(); message('Wallet restored. Your balance is verified.', 'success'); }
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
  setScreen(`<div class="row"><h2>Your private wallet</h2><button class="text-button small" id="lock">Lock</button></div><div class="balance" id="balance">${balance === null ? '—' : balance}<small> test units</small></div><p class="hint">Verified from finalized payment history.</p><div class="row"><button class="primary" id="send">Send</button><button class="secondary" id="receive">Receive</button></div><button class="secondary" id="fund">Add ${Number(session.faucet_amount || 100).toLocaleString()} test units</button>${session.recipient_withdrawals ? '<button class="secondary" id="withdraw">Withdraw publicly</button><p class="hint" id="public-balance"></p>' : ''}<p class="hint small">Fees are paid by the local test sponsor. Solana funding is coming later.</p><div id="receipt"></div><div class="split row"><button class="text-button small" id="refresh">Refresh balance</button><button class="text-button small" id="backup">Recovery file</button></div><div id="recovery-controls"></div>`);
  on('lock', 'click', lock); on('receive', 'click', receive); on('send', 'click', send);
  if (session.recipient_withdrawals) { on('withdraw', 'click', () => withdraw()); document.querySelector('#public-balance').textContent = `Public account: ${publicBalance === null ? '—' : publicBalance} test units on this chain.`; }
  on('refresh', 'click', () => work('Verifying finalized payment history…', dashboard));
  on('backup', 'click', recovery);
  on('fund', 'click', () => payment('fund'));
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
    button.addEventListener('click', () => work('Checking finalized recovery state…', async () => { const result = await api(session.pending ? 'resolve' : 'reclaim'); if (result.accepted) receipt = { ...result, staging_rent_reclaimed: !result.staging_recovery_required }; await dashboard(); message(result.accepted ? 'The previous payment finalized. Recover its upload rent if prompted.' : 'Recovery step completed.', 'success'); }));
    controls.append(description, button);
  }
}
async function dashboard() {
  const result = await api('balance'); balance = result.balance; publicAddress = result.public_address || ''; publicBalance = result.public_balance ?? null; minimumPublicWithdrawal = result.minimum_public_withdrawal ?? null; renderDashboard();
}
function receive() {
  setScreen(`<h2>Receive privately</h2><p class="caption">Share this address with someone using this local network.</p><p class="address" id="address"></p><button class="primary" id="copy">Copy receiving address</button><button class="secondary" id="back">Back to wallet</button><p class="hint">This is a private address for this chain. It cannot receive SOL or USDC from Solana.</p>`);
  document.querySelector('#address').textContent = address;
  on('copy', 'click', async () => { try { await navigator.clipboard.writeText(address); message('Receiving address copied.', 'success'); } catch { message('Select the address above and copy it.'); } });
  on('back', 'click', renderDashboard);
}
function send(draft = {}) {
  if (session.pending || session.staging) return renderDashboard();
  setScreen(`<h2>Send privately</h2><p class="caption">Pay a private address on this local network.</p><form id="send-form"><label for="recipient">Recipient address</label><textarea id="recipient" required rows="3" maxlength="140" placeholder="npriv1…" spellcheck="false" autocapitalize="off" autocorrect="off"></textarea><label for="amount">Amount in test units</label><input id="amount" type="number" inputmode="numeric" min="1" step="1" required><button class="primary">Review payment</button></form><button class="text-button back" id="back">Back to wallet</button>`);
  document.querySelector('#recipient').value = draft.recipient || '';
  document.querySelector('#amount').value = draft.amount || '';
  on('back', 'click', renderDashboard);
  on('send-form', 'submit', event => { event.preventDefault(); const recipient = document.querySelector('#recipient').value.trim(), amount = Number(document.querySelector('#amount').value); if (!recipient.startsWith('npriv1') || !Number.isSafeInteger(amount) || amount < 1 || amount > balance) return message('Enter a private receiving address and an amount within your balance.', 'error'); review(recipient, amount); });
}
function withdraw(draft = {}) {
  if (session.pending || session.staging) return renderDashboard();
  setScreen(`<h2>Withdraw publicly</h2><p class="caption">Move private funds to a public account on this chain.</p><form id="withdraw-form"><label for="recipient">Public destination address</label><textarea id="recipient" required rows="2" maxlength="44" spellcheck="false" autocapitalize="off" autocorrect="off"></textarea><p class="hint">The default account is controlled by your recovery seed. This sends this chain's native coin, not SOL on Solana.</p><label for="amount">Amount in test units</label><input id="amount" type="number" inputmode="numeric" min="1" step="1" required><p class="hint" id="withdraw-minimum"></p><button class="primary">Review withdrawal</button></form><button class="text-button back" id="back">Back to wallet</button>`);
  document.querySelector('#recipient').value = draft.recipient || publicAddress;
  document.querySelector('#amount').value = draft.amount || '';
  document.querySelector('#withdraw-minimum').textContent = minimumPublicWithdrawal > 1 ? `Your public account needs at least ${minimumPublicWithdrawal} units for its first withdrawal. The sponsor pays fees and protocol rent.` : 'The sponsor pays fees and protocol rent; your destination receives the full withdrawal amount.';
  on('back', 'click', renderDashboard);
  on('withdraw-form', 'submit', event => {
    event.preventDefault();
    const recipient = document.querySelector('#recipient').value.trim(), amount = Number(document.querySelector('#amount').value);
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(recipient) || !Number.isSafeInteger(amount) || amount < 1 || amount > balance) return message('Enter a public address and a whole amount within your private balance.', 'error');
    if (recipient === publicAddress && amount < minimumPublicWithdrawal) return message(`Withdraw at least ${minimumPublicWithdrawal} units to create this public account.`, 'error');
    review(recipient, amount, 'withdraw');
  });
}
function review(recipient, amount, action = 'send') {
  const withdrawing = action === 'withdraw';
  setScreen(`<h2>${withdrawing ? 'Review public withdrawal' : 'Review payment'}</h2><div class="balance" id="review-amount"></div><p class="hint">To</p><p class="address" id="review-address"></p><p class="hint">${withdrawing ? 'The amount and destination become public on this chain. The sponsor pays fees and rent, and receives none of your withdrawal.' : 'The local test sponsor pays the network fees.'}</p><button class="primary" id="confirm-send">${withdrawing ? 'Withdraw publicly' : 'Send payment'}</button><button class="secondary" id="back">${withdrawing ? 'Edit withdrawal' : 'Edit payment'}</button>`);
  document.querySelector('#review-amount').textContent = `${amount} test units`; document.querySelector('#review-address').textContent = recipient;
  on('back', 'click', () => withdrawing ? withdraw({ recipient, amount }) : send({ recipient, amount })); on('confirm-send', 'click', () => payment(action, { recipient, amount }));
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
try { session = await (await fetch('/api/session')).json(); welcome(); }
catch { message('The local wallet is unavailable. Restart the local wallet session.', 'error'); }
