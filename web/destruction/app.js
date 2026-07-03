const ICON_PASS = `<svg class="verify-check__icon verify-check__icon--pass" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd"/></svg>`;
const ICON_FAIL = `<svg class="verify-check__icon verify-check__icon--fail" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd"/></svg>`;
const ICON_PENDING = `<svg class="verify-check__icon verify-check__icon--pending" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><circle cx="10" cy="10" r="6" opacity="0.35"/></svg>`;
const FILE_ICON = `<svg class="verify-file-chip__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>`;

const CHECK_LABELS = {
  signature_valid: 'Signature Valid',
  hardware_genuine: 'Hardware Genuine',
  key_binding: 'Key Bound to Silicon',
  destruction_attestation_hash: 'Attestation Hash',
  zeroization_evidence: 'Zeroization Evidence',
  salt_epoch: 'Salt Epoch',
  destruction_tenant_hash: 'Tenant Hash',
  freshness: 'Freshness',
  registry_quorum: 'Registry Quorum',
  proof_signature: 'Proof Signature',
  merkle_root: 'Unified Merkle Root',
  rekor_log_index: 'Rekor Log Index',
};

const THEME_STORAGE_KEY = 'nexqloud-verify-theme';

let wasmReady = false;
let proofFile = null;
let receiptFiles = [];
let advancedMode = null;

function $(id) {
  return document.getElementById(id);
}

function getStoredTheme() {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') return stored;
  } catch (_) {}
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
  const isDark = theme === 'dark';
  document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch (_) {}

  const toggle = $('theme-toggle');
  if (toggle) {
    toggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
    toggle.setAttribute('title', isDark ? 'Light mode' : 'Dark mode');
  }

  const wordmark = document.querySelector('.verify-brand__wordmark');
  if (wordmark) {
    wordmark.src = isDark ? wordmark.dataset.srcDark : wordmark.dataset.srcLight;
  }
}

function setupThemeToggle() {
  applyTheme(getStoredTheme());
  const toggle = $('theme-toggle');
  if (!toggle) return;
  toggle.addEventListener('click', () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    applyTheme(isDark ? 'light' : 'dark');
  });
}

async function initWasm() {
  const go = new Go();
  let buildID = '';
  try {
    const buildResp = await fetch('../wasm_build.txt', { cache: 'no-store' });
    if (buildResp.ok) buildID = (await buildResp.text()).trim();
  } catch (_) {}

  const wasmURL = buildID ? `../main.wasm?v=${encodeURIComponent(buildID)}` : '../main.wasm';
  const response = await fetch(wasmURL, { cache: 'no-store' });
  const bytes = await response.arrayBuffer();
  const result = await WebAssembly.instantiate(bytes, go.importObject);
  go.run(result.instance);
  wasmReady = true;
}

function truncateHex(s) {
  if (!s) return '';
  const clean = String(s).replace(/^sha256:/, '');
  if (clean.length <= 16) return clean;
  return `${clean.slice(0, 8)}…${clean.slice(-8)}`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setStatus(text, loading = true) {
  const status = $('status');
  $('status-text').textContent = text;
  $('status-spinner').hidden = !loading;
  status.hidden = false;
}

function hideStatus() {
  $('status').hidden = true;
}

function formatFileSize(bytes) {
  if (!Number.isFinite(bytes) || bytes < 1024) return `${bytes || 0} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatOperatorTitle(operatorID) {
  const id = String(operatorID || '').trim();
  if (!id) return 'Operator';
  const suffix = id.replace(/^operator-/i, '').toUpperCase();
  return suffix ? `Operator ${suffix}` : id;
}

function renderFileChip(file, { onRemove }) {
  const li = document.createElement('li');
  li.className = 'verify-file-chip';
  li.innerHTML = `
    ${FILE_ICON}
    <div class="verify-file-chip__body">
      <span class="verify-file-chip__name">${escapeHtml(file.name)}</span>
      <span class="verify-file-chip__meta">${escapeHtml(formatFileSize(file.size))} · JSON</span>
    </div>
    <button type="button" class="verify-file-chip__remove" aria-label="Remove ${escapeHtml(file.name)}">×</button>
  `;
  li.querySelector('.verify-file-chip__remove').addEventListener('click', (e) => {
    e.stopPropagation();
    onRemove();
  });
  return li;
}

function updateVerifyButton() {
  $('verify-btn').disabled = !(wasmReady && proofFile && receiptFiles.length > 0);
}

function renderProofFile() {
  const list = $('proof-file-list');
  const attached = $('proof-attached');
  const card = $('proof-card');
  list.innerHTML = '';

  if (!proofFile) {
    attached.hidden = true;
    card.classList.remove('verify-upload-card--has-files');
    return;
  }

  attached.hidden = false;
  card.classList.add('verify-upload-card--has-files');
  list.appendChild(renderFileChip(proofFile, {
    onRemove: () => {
      proofFile = null;
      $('proof-input').value = '';
      renderProofFile();
      updateVerifyButton();
    },
  }));
}

function renderReceiptList() {
  const list = $('receipt-file-list');
  const attached = $('receipts-attached');
  const card = $('receipts-card');
  list.innerHTML = '';

  if (!receiptFiles.length) {
    attached.hidden = true;
    card.classList.remove('verify-upload-card--has-files');
    return;
  }

  attached.hidden = false;
  card.classList.add('verify-upload-card--has-files');
  receiptFiles.forEach((file, index) => {
    list.appendChild(renderFileChip(file, {
      onRemove: () => {
        receiptFiles.splice(index, 1);
        renderReceiptList();
        updateVerifyButton();
      },
    }));
  });
}

function setProofFile(file) {
  if (!file.name.endsWith('.json')) {
    alert('Please upload a JSON proof file');
    return;
  }
  proofFile = file;
  renderProofFile();
  updateVerifyButton();
}

function addReceiptFiles(files) {
  const incoming = Array.from(files).filter((f) => f.name.endsWith('.json'));
  if (!incoming.length) {
    alert('Please upload JSON receipt files');
    return;
  }
  for (const file of incoming) {
    if (!receiptFiles.some((f) => f.name === file.name && f.size === file.size)) {
      receiptFiles.push(file);
    }
  }
  renderReceiptList();
  updateVerifyButton();
}

function resetAll() {
  proofFile = null;
  receiptFiles = [];
  $('proof-input').value = '';
  $('receipts-input').value = '';
  renderProofFile();
  renderReceiptList();
  $('results').hidden = true;
  if (advancedMode) advancedMode.resetAdvanced();
  updateVerifyButton();
}

function setupDropZone(zoneId, inputId, onFiles) {
  const zone = $(zoneId);
  const input = $(inputId);
  const attached = zoneId === 'proof-drop' ? $('proof-attached') : $('receipts-attached');

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      input.click();
    }
  });
  if (attached) {
    attached.addEventListener('click', (e) => e.stopPropagation());
  }
  input.addEventListener('change', (e) => {
    const files = e.target.files;
    if (!files || !files.length) return;
    onFiles(files);
  });
  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('verify-drop--active');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('verify-drop--active'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('verify-drop--active');
    if (e.dataTransfer.files.length) onFiles(e.dataTransfer.files);
  });
}

async function fetchRegistryRecord(url, tenantID) {
  const endpoint = `${url.replace(/\/$/, '')}/records/${encodeURIComponent(tenantID)}`;
  const resp = await fetch(endpoint);
  if (!resp.ok) throw new Error(`Registry returned ${resp.status}`);
  return resp.text();
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
  return { integratedTime, logIndex };
}

function groupChecks(checks) {
  const groups = [];
  let bucket = [];
  for (const check of checks) {
    if (check.id === 'rekor_log_index') continue;
    bucket.push(check);
    if (check.id.startsWith('destruction_operator_id:')) {
      groups.push({ title: formatOperatorTitle(check.detail), checks: bucket });
      bucket = [];
    }
  }
  if (bucket.length) {
    groups.push({ title: 'Unified Proof & Quorum', checks: bucket });
  }
  return groups;
}

function renderCheck(check) {
  const li = document.createElement('li');
  const passed = !!check.ok;
  let detail = check.detail || '';
  if (check.id === 'hardware_genuine' && passed) {
    detail = check.detail || 'Full chain verified: VCEK → ASK → ARK matched to AMD Root';
  }
  const hashDisplay = check.hash
    ? `<span class="verify-check__hash">(${escapeHtml(check.hash)})</span>`
    : '';
  const label = check.label || CHECK_LABELS[check.id] || check.id;
  li.className = `verify-check ${passed ? 'verify-check--pass' : 'verify-check--fail'}`;
  li.innerHTML = `
    ${passed ? ICON_PASS : ICON_FAIL}
    <div class="verify-check__body">
      <div class="verify-check__label">${escapeHtml(label)}${hashDisplay}</div>
      <div class="verify-check__detail">${escapeHtml(detail)}</div>
    </div>
  `;
  return li;
}

function renderLedger(logIndex, info, error) {
  const section = $('ledger-section');
  const list = $('ledger-info');
  section.hidden = false;
  list.innerHTML = '';
  const searchUrl = `https://search.sigstore.dev/?logIndex=${encodeURIComponent(logIndex)}`;
  const li = document.createElement('li');
  if (info) {
    li.className = 'verify-check verify-check--pass';
    li.innerHTML = `
      ${ICON_PASS}
      <div class="verify-check__body">
        <div class="verify-check__label">Public Ledger Timestamp</div>
        <div class="verify-check__detail">
          <a href="${searchUrl}" target="_blank" rel="noopener">${escapeHtml(info.integratedTime || 'unknown')}</a>
          · log index ${escapeHtml(logIndex)}
        </div>
      </div>
    `;
  } else {
    li.className = 'verify-check verify-check--fail';
    li.innerHTML = `
      ${ICON_FAIL}
      <div class="verify-check__body">
        <div class="verify-check__label">Public Ledger</div>
        <div class="verify-check__detail">
          Could not fetch Rekor entry: ${escapeHtml(error)}.
          <a href="${searchUrl}" target="_blank" rel="noopener">View on search.sigstore.dev</a>
        </div>
      </div>
    `;
  }
  list.appendChild(li);
}

function renderPendingCheck(label, detail = 'Running…') {
  const li = document.createElement('li');
  li.className = 'verify-check verify-check--pending';
  li.innerHTML = `
    ${ICON_PENDING}
    <div class="verify-check__body">
      <div class="verify-check__label">${escapeHtml(label)}</div>
      <div class="verify-check__detail">${escapeHtml(detail)}</div>
    </div>
  `;
  return li;
}

function showPendingChecklist(receiptCount) {
  const results = $('results');
  const groupsEl = $('check-groups');
  results.hidden = false;
  $('overall-badge').className = 'verify-badge';
  $('overall-badge').textContent = '';
  $('ledger-section').hidden = true;
  groupsEl.innerHTML = '';

  const perOperator = [
    'Signature Valid',
    'Hardware Genuine',
    'Key Bound to Silicon',
    'Attestation Hash',
    'Zeroization Evidence',
    'Salt Epoch',
    'Tenant Hash',
    'Freshness',
  ];
  for (let i = 0; i < receiptCount; i++) {
    const section = document.createElement('section');
    section.className = 'verify-check-group';
    section.innerHTML = `<h3 class="verify-check-group__title">Operator receipt ${i + 1}</h3>`;
    const list = document.createElement('ul');
    list.className = 'verify-checklist';
    list.setAttribute('role', 'list');
    for (const label of perOperator) {
      list.appendChild(renderPendingCheck(label));
    }
    section.appendChild(list);
    groupsEl.appendChild(section);
  }

  const proofSection = document.createElement('section');
  proofSection.className = 'verify-check-group';
  proofSection.innerHTML = '<h3 class="verify-check-group__title">Unified Proof & Quorum</h3>';
  const proofList = document.createElement('ul');
  proofList.className = 'verify-checklist';
  proofList.setAttribute('role', 'list');
  for (const label of [
    'Registry Quorum',
    'Proof Signature',
    'Unified Merkle Root',
    'Rekor Log Index',
  ]) {
    proofList.appendChild(renderPendingCheck(label));
  }
  proofSection.appendChild(proofList);
  groupsEl.appendChild(proofSection);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function revealChecksProgressively(result, proof) {
  const groups = groupChecks(result.checks);
  const groupsEl = $('check-groups');
  groupsEl.innerHTML = '';

  for (const group of groups) {
    const section = document.createElement('section');
    section.className = 'verify-check-group';
    section.innerHTML = `<h3 class="verify-check-group__title">${escapeHtml(group.title)}</h3>`;
    const list = document.createElement('ul');
    list.className = 'verify-checklist';
    list.setAttribute('role', 'list');
    section.appendChild(list);
    groupsEl.appendChild(section);

    for (const check of group.checks) {
      list.appendChild(renderPendingCheck(check.label || CHECK_LABELS[check.id] || check.id));
      await delay(80);
      list.lastElementChild.replaceWith(renderCheck(check));
    }
  }

  const pkg = proof.package || {};
  const destructionID = result.destruction_id || pkg.destruction_id || '—';
  const merkle = pkg.merkle_root ? truncateHex(pkg.merkle_root) : '—';
  $('proof-meta').textContent = `destruction_id: ${destructionID} · merkle_root: ${merkle} · quorum: ${(pkg.quorum || []).join(', ')}`;

  const badge = $('overall-badge');

  if (result.overall_ok) {
    badge.className = 'verify-badge verify-badge--success';
    badge.innerHTML = '<span class="verify-badge__dot" aria-hidden="true"></span>Verified';
  } else {
    badge.className = 'verify-badge verify-badge--danger';
    badge.innerHTML = '<span class="verify-badge__dot" aria-hidden="true"></span>Failed';
  }

  const metaParts = [];
  if (result.tenant_id_hash) metaParts.push(`tenant_id_hash: ${truncateHex(result.tenant_id_hash)}`);
  if (result.log_index) metaParts.push(`rekor log_index: ${result.log_index}`);
  $('result-meta').textContent = metaParts.join(' · ');
}

async function runVerification() {
  if (!wasmReady || !proofFile || !receiptFiles.length) return;

  setStatus('Reading proof and receipts…');
  const proofText = await proofFile.text();
  let proof;
  try {
    proof = JSON.parse(proofText);
  } catch {
    alert('Invalid proof JSON');
    hideStatus();
    return;
  }

  const receipts = [];
  for (const file of receiptFiles) {
    try {
      receipts.push(JSON.parse(await file.text()));
    } catch {
      alert(`Invalid JSON in ${file.name}`);
      hideStatus();
      return;
    }
  }

  let registryRecordJSON = '';
  const registryURL = $('registry-url').value.trim();
  const tenantID = $('tenant-id').value.trim();
  if (registryURL && tenantID) {
    setStatus('Fetching registry record…');
    try {
      registryRecordJSON = await fetchRegistryRecord(registryURL, tenantID);
    } catch (err) {
      alert(`Registry fetch failed: ${err.message}`);
      hideStatus();
      return;
    }
  }

  setStatus('Running cryptographic verification in WebAssembly…');
  showPendingChecklist(receipts.length);
  hideStatus();

  let result;
  try {
    const out = globalThis.verifyDeletion(
      proofText,
      JSON.stringify(receipts),
      registryRecordJSON,
      ''
    );
    result = JSON.parse(out);
    if (result.error) throw new Error(result.error);
  } catch (err) {
    alert(`Verification error: ${err.message}`);
    $('results').hidden = true;
    return;
  }

  await revealChecksProgressively(result, proof);

  const receiptEntries = receiptFiles.map((file, index) => ({
    file,
    data: receipts[index],
  }));
  if (advancedMode) {
    advancedMode.updateAdvanced(proof, proofFile?.name || 'Unified proof', receiptEntries, result);
  }

  let rekorInfo = null;
  let rekorError = null;
  const logIndex = result.log_index || proof.log_index;
  if (logIndex) {
    setStatus('Querying Sigstore transparency log…');
    try {
      rekorInfo = await fetchRekorEntry(logIndex);
    } catch (err) {
      rekorError = err.message;
    }
  }

  hideStatus();
  if (logIndex) renderLedger(logIndex, rekorInfo, rekorError);
  else $('ledger-section').hidden = true;
}

async function boot() {
  setupThemeToggle();
  advancedMode = initDestructionAdvanced();
  setupDropZone('proof-drop', 'proof-input', (files) => setProofFile(files[0]));
  setupDropZone('receipts-drop', 'receipts-input', (files) => addReceiptFiles(files));
  $('verify-btn').addEventListener('click', runVerification);
  $('reset-btn').addEventListener('click', resetAll);

  setStatus('Loading WebAssembly verifier…');
  try {
    await initWasm();
    hideStatus();
    updateVerifyButton();
  } catch (err) {
    $('status-text').textContent = `Failed to load Wasm module: ${err.message}`;
    $('status-spinner').hidden = true;
  }
}

boot();
