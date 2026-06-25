const CHECK_LABELS = {
  signature_valid: 'Signature Valid',
  hardware_genuine: 'Hardware Genuine',
  key_binding: 'Key Bound to Silicon',
  code_legit: 'Code Legit',
  model_legit: 'Model Legit',
  gpu_wiped: 'GPU Wiped',
  freshness: 'Freshness',
};

const CHECK_HINTS = {
  signature_valid: 'ed25519',
  hardware_genuine: 'VCEK → ASK → ARK',
  key_binding: 'REPORT_DATA match',
  code_legit: 'measurement',
  model_legit: 'catalog hash',
  gpu_wiped: 'policy enforced',
  freshness: 'nonce challenge',
};

const ICON_PASS = `<svg class="verify-check__icon verify-check__icon--pass" viewBox="0 0 18 18" fill="none" aria-hidden="true"><circle cx="9" cy="9" r="8" stroke="currentColor" stroke-width="1.5"/><path d="M5.5 9.2l2.1 2.1 4.9-5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const ICON_FAIL = `<svg class="verify-check__icon verify-check__icon--fail" viewBox="0 0 18 18" fill="none" aria-hidden="true"><circle cx="9" cy="9" r="8" stroke="currentColor" stroke-width="1.5"/><path d="M6.2 6.2l5.6 5.6M11.8 6.2l-5.6 5.6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`;

let wasmReady = false;

async function initWasm() {
  const go = new Go();
  const response = await fetch('main.wasm');
  const bytes = await response.arrayBuffer();
  const result = await WebAssembly.instantiate(bytes, go.importObject);
  go.run(result.instance);
  wasmReady = true;
}

async function fetchRekorEntry(logIndex) {
  const url = `https://rekor.sigstore.dev/api/v1/log/entries?logIndex=${encodeURIComponent(logIndex)}`;
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Rekor lookup failed: ${resp.status}`);
  const data = await resp.json();

  const entry = Object.values(data)[0];
  if (!entry) throw new Error('Rekor entry not found');

  const integratedTime = entry.integratedTime
    ? new Date(entry.integratedTime * 1000).toISOString()
    : null;

  let bodyHash = '';
  if (entry.body) {
    const raw = atob(entry.body);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    bodyHash = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  return { integratedTime, bodyHash, logIndex };
}

function truncateHex(s) {
  if (!s) return '';
  const clean = s.replace(/^sha256:/, '');
  if (clean.length <= 16) return clean;
  return `${clean.slice(0, 8)}…${clean.slice(-8)}`;
}

function renderCheck(check) {
  const li = document.createElement('li');
  const passed = check.ok;

  const hint = CHECK_HINTS[check.id] || '';
  const hashDisplay = check.hash
    ? `<span class="verify-check__hash">(${truncateHex(check.hash)})</span>`
    : '';

  let detail = check.detail || hint;
  if (check.id === 'hardware_genuine' && check.chain_validated) {
    detail = 'Full chain verified: VCEK → ASK → ARK matched to AMD Root';
  }

  li.className = `verify-check ${passed ? 'verify-check--pass' : 'verify-check--fail'}`;
  li.innerHTML = `
    ${passed ? ICON_PASS : ICON_FAIL}
    <div class="verify-check__body">
      <div class="verify-check__label">
        ${check.label || CHECK_LABELS[check.id] || check.id}
        ${hashDisplay}
      </div>
      <div class="verify-check__detail">${detail}</div>
    </div>
  `;
  return li;
}

function renderLedger(info) {
  const section = document.getElementById('ledger-section');
  const list = document.getElementById('ledger-info');
  section.hidden = false;
  list.innerHTML = '';

  const searchUrl = `https://search.sigstore.dev/?logIndex=${info.logIndex}`;
  const timeStr = info.integratedTime || 'unknown';
  const hashStr = info.bodyHash ? truncateHex(info.bodyHash) : '—';

  const li = document.createElement('li');
  li.className = 'verify-check verify-check--pass';
  li.innerHTML = `
    ${ICON_PASS}
    <div class="verify-check__body">
      <div class="verify-check__label">
        Public Ledger Timestamp
        <span class="verify-check__hash">(${hashStr})</span>
      </div>
      <div class="verify-check__detail">
        <a href="${searchUrl}" target="_blank" rel="noopener">${timeStr}</a>
        · log index ${info.logIndex}
      </div>
    </div>
  `;
  list.appendChild(li);
}

function renderLedgerError(logIndex, message) {
  const section = document.getElementById('ledger-section');
  const list = document.getElementById('ledger-info');
  section.hidden = false;
  list.innerHTML = '';

  const searchUrl = `https://search.sigstore.dev/?logIndex=${logIndex}`;
  const li = document.createElement('li');
  li.className = 'verify-check verify-check--fail';
  li.innerHTML = `
    ${ICON_FAIL}
    <div class="verify-check__body">
      <div class="verify-check__label">Public Ledger</div>
      <div class="verify-check__detail">
        Could not fetch Rekor entry for log index ${logIndex}: ${message}.
        <a href="${searchUrl}" target="_blank" rel="noopener">View on search.sigstore.dev</a>
      </div>
    </div>
  `;
  list.appendChild(li);
}

function setStatus(text, loading = true) {
  const status = document.getElementById('status');
  const spinner = document.getElementById('status-spinner');
  const statusText = document.getElementById('status-text');
  status.hidden = false;
  statusText.textContent = text;
  spinner.hidden = !loading;
}

function hideStatus() {
  document.getElementById('status').hidden = true;
}

async function runWasmVerify(receipt) {
  if (!wasmReady) throw new Error('Wasm module not loaded');

  const challenge = document.getElementById('challenge-input').value.trim();
  const receiptJSON = JSON.stringify(receipt);
  const resultJSON = globalThis.verifyReceipt(receiptJSON, challenge);
  const result = JSON.parse(resultJSON);

  if (result.error) throw new Error(result.error);
  return result;
}

async function handleFile(file) {
  if (!file.name.endsWith('.json')) {
    alert('Please upload a receipt.json file');
    return;
  }

  setStatus('Reading receipt…');
  const text = await file.text();
  let receipt;
  try {
    receipt = JSON.parse(text);
  } catch {
    alert('Invalid JSON file');
    hideStatus();
    return;
  }

  setStatus('Running cryptographic verification in WebAssembly…');
  let wasmResult;
  try {
    wasmResult = await runWasmVerify(receipt);
  } catch (err) {
    alert(`Verification error: ${err.message}`);
    hideStatus();
    return;
  }

  const logIndex = wasmResult.log_index || receipt.log_index;
  let rekorInfo = null;
  let rekorError = null;
  if (logIndex) {
    setStatus('Querying Sigstore transparency log…');
    try {
      rekorInfo = await fetchRekorEntry(logIndex);
    } catch (err) {
      rekorError = err.message;
      console.warn('Rekor lookup failed:', err);
    }
  }

  hideStatus();
  renderResults(wasmResult, rekorInfo, rekorError);
}

function renderResults(result, rekorInfo, rekorError = null) {
  const results = document.getElementById('results');
  const checklist = document.getElementById('checklist');
  const badge = document.getElementById('overall-badge');
  const meta = document.getElementById('receipt-meta');

  results.hidden = false;
  checklist.innerHTML = '';

  for (const check of result.checks) {
    checklist.appendChild(renderCheck(check));
  }

  if (rekorInfo) {
    renderLedger(rekorInfo);
  } else if (rekorError) {
    renderLedgerError(result.log_index, rekorError);
  } else {
    document.getElementById('ledger-section').hidden = true;
  }

  if (result.overall_ok) {
    badge.textContent = 'Verified';
    badge.className = 'verify-badge verify-badge--success';
    badge.innerHTML = '<span class="verify-badge__dot" aria-hidden="true"></span>Verified';
  } else {
    badge.textContent = 'Failed';
    badge.className = 'verify-badge verify-badge--danger';
    badge.innerHTML = '<span class="verify-badge__dot" aria-hidden="true"></span>Failed';
  }

  if (result.receipt_id) {
    meta.textContent = `receipt_id: ${result.receipt_id}`;
  }
}

function setupDropZone() {
  const zone = document.getElementById('drop-zone');
  const input = document.getElementById('file-input');

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      input.click();
    }
  });

  input.addEventListener('change', (e) => {
    if (e.target.files[0]) handleFile(e.target.files[0]);
  });

  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('verify-drop--active');
  });
  zone.addEventListener('dragleave', () => {
    zone.classList.remove('verify-drop--active');
  });
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('verify-drop--active');
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  setupDropZone();
  setStatus('Loading WebAssembly verifier…');
  try {
    await initWasm();
    hideStatus();
  } catch (err) {
    setStatus(`Failed to load Wasm: ${err.message}`, false);
  }
});
