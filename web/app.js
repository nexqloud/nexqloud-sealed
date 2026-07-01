const CHECK_LABELS = {
  signature_valid: 'Signature Valid',
  hardware_genuine: 'Hardware Genuine',
  key_binding: 'Key Bound to Silicon',
  code_legit: 'Code Legit',
  model_legit: 'Model Legit',
  gpu_wiped: 'GPU Wiped',
  freshness: 'Freshness',
  derivation_operator_id: 'Operator ID',
  derivation_attestation_hash: 'Attestation Hash',
  derivation_tenant_hash: 'Tenant ID Hash',
  derivation_key_version: 'Key Version',
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
const ICON_SKIPPED = `<svg class="verify-check__icon verify-check__icon--skipped" viewBox="0 0 18 18" fill="none" aria-hidden="true"><circle cx="9" cy="9" r="8" stroke="currentColor" stroke-width="1.5"/><circle cx="9" cy="5.4" r="0.85" fill="currentColor"/><path d="M9 7.8V13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`;

const DERIVATION_RECEIPT_TOPICS = [
  {
    id: 'signature',
    checkId: 'signature_valid',
    swatchClass: 'signature',
    label: 'Signature Valid',
    description: 'Ed25519 signature over the RFC 8785 canonical package, verified with pubkey.',
    fieldHint: 'Look for "signature", "pubkey", and all fields inside "package".',
    plainEnglish: 'The sealing operator signed the derivation claims with its enclave private key. We verify that signature using the public key in the receipt.',
  },
  {
    id: 'hardware',
    checkId: 'hardware_genuine',
    swatchClass: 'hardware',
    label: 'Hardware Genuine',
    description: 'AMD SEV-SNP report plus cert_chain (VCEK → ASK → ARK).',
    fieldHint: 'Look for "cert_chain" and key fields inside "attestation.report".',
    plainEnglish: 'This proves the derivation attestation came from real AMD silicon with a validated certificate chain.',
  },
  {
    id: 'key_binding',
    checkId: 'key_binding',
    swatchClass: 'key_binding',
    label: 'Key Bound to Silicon',
    description: 'Links pubkey + nonce into hardware attestation reportData.',
    fieldHint: 'Look for "reportData" and root-level "nonce".',
    plainEnglish: 'Confirms the signing key used for the derivation receipt was bound into the hardware attestation.',
  },
  {
    id: 'derivation_operator',
    checkId: 'derivation_operator_id',
    swatchClass: 'derivation',
    label: 'Operator ID',
    description: 'Federated operator that performed key derivation.',
    fieldHint: 'Look for "operator_id" inside package.',
    plainEnglish: 'Identifies which federation operator (for example operator-a) created this derivation receipt.',
  },
  {
    id: 'derivation_attestation',
    checkId: 'derivation_attestation_hash',
    swatchClass: 'derivation',
    label: 'Attestation Hash',
    description: 'SHA-256 of the attestation bytes, committed in the signed package.',
    fieldHint: 'Look for "attestation_hash" inside package.',
    plainEnglish: 'Binds the signed package to the exact hardware attestation blob included in the receipt.',
  },
  {
    id: 'derivation_tenant',
    checkId: 'derivation_tenant_hash',
    swatchClass: 'derivation',
    label: 'Tenant ID Hash',
    description: 'SHA-256 commitment to the tenant identifier.',
    fieldHint: 'Look for "tenant_id_hash" inside package.',
    plainEnglish: 'Shows which tenant federation context this derivation belongs to, without revealing the raw tenant ID.',
  },
  {
    id: 'derivation_key_version',
    checkId: 'derivation_key_version',
    swatchClass: 'derivation',
    label: 'Key Version',
    description: 'Federation key version used during derivation.',
    fieldHint: 'Look for "key_version" inside package.',
    plainEnglish: 'Records which key version was active when the operator derived the sealing key.',
  },
  {
    id: 'signed_only',
    checkId: null,
    swatchClass: 'signed_only',
    label: 'Signed only',
    description: 'Integrity via signature, not independently validated.',
    fieldHint: 'Look for schema and timestamp inside package.',
    plainEnglish: 'These fields are covered by the enclave signature but are not checked against external catalogs.',
    statusOverride: 'info',
  },
  {
    id: 'ledger',
    checkId: null,
    swatchClass: 'ledger',
    label: 'Public Ledger',
    description: 'Sigstore Rekor transparency log index (browser lookup).',
    fieldHint: 'Look for "log_index" at the root.',
    plainEnglish: 'An optional lookup in Sigstore\'s public transparency log for when this derivation receipt was recorded.',
    statusOverride: 'ledger',
  },
];

const RECEIPT_TOPICS = [
  {
    id: 'signature',
    checkId: 'signature_valid',
    swatchClass: 'signature',
    label: 'Signature Valid',
    description: 'Ed25519 signature over the RFC 8785 canonical package, verified with pubkey.',
    fieldHint: 'Look for "signature", "pubkey", and all fields inside "package".',
    plainEnglish: 'The secure enclave signed the receipt claims with its private key. We verify that signature using the public key in the receipt, so you know nobody changed the package after it was signed.',
  },
  {
    id: 'hardware',
    checkId: 'hardware_genuine',
    swatchClass: 'hardware',
    label: 'Hardware Genuine',
    description: 'AMD SEV-SNP report plus cert_chain (VCEK → ASK → ARK).',
    fieldHint: 'Look for "cert_chain" and key fields inside "attestation.report".',
    plainEnglish: 'This proves the attestation came from real AMD silicon. We validate the certificate chain from the CPU up to AMD root keys, and confirm the hardware report was signed by that CPU.',
  },
  {
    id: 'unused_chain',
    checkId: null,
    swatchClass: 'unused',
    label: 'Unused duplicate chain',
    description: 'Not used by the verifier — cert_chain is authoritative.',
    fieldHint: 'Hidden "certificateChain" block (expand to inspect).',
    plainEnglish: 'A second copy of the certificates nested inside attestation. The verifier only uses the top-level cert_chain field, so editing this hidden copy alone would not fail verification.',
    statusOverride: 'info',
  },
  {
    id: 'key_binding',
    checkId: 'key_binding',
    swatchClass: 'key_binding',
    label: 'Key Bound to Silicon',
    description: 'Links pubkey + nonce into hardware attestation (reportData or Azure user-data).',
    fieldHint: 'Look for "reportData" and "runtime_claims_json.user-data".',
    plainEnglish: 'This checks that the signing key really lived inside that specific CPU enclave. The hardware attestation must include a fingerprint of the public key combined with the session nonce.',
  },
  {
    id: 'code_legit',
    checkId: 'code_legit',
    swatchClass: 'code_legit',
    label: 'Code Legit',
    description: 'Enclave measurement compared to verifier allowlist.',
    fieldHint: 'Look for "enclave_measurement" inside package.',
    plainEnglish: 'Confirms the enclave was running approved software. The enclave_measurement value is compared against a list of known-good builds that this verifier trusts.',
  },
  {
    id: 'model_legit',
    checkId: 'model_legit',
    swatchClass: 'model_legit',
    label: 'Model Legit',
    description: 'Model commitment hash compared to catalog.',
    fieldHint: 'Look for "model_commitment" inside package.',
    plainEnglish: 'Confirms which AI model produced the result. The model_commitment hash is checked against an allowed model catalog so only approved models pass.',
  },
  {
    id: 'gpu_wiped',
    checkId: 'gpu_wiped',
    swatchClass: 'gpu_wiped',
    label: 'GPU Wiped',
    description: 'GPU isolation policy hash and zeroization certificate.',
    fieldHint: 'Look for "gpu_policy_hash" and "zeroization_cert" inside package.',
    plainEnglish: 'Checks that GPU memory was wiped and isolation rules were enforced before inference. We compare the policy hash and wipe certificate against expected values.',
  },
  {
    id: 'freshness',
    checkId: 'freshness',
    swatchClass: 'freshness',
    label: 'Freshness',
    description: 'Session nonce — compared to your challenge input when supplied.',
    fieldHint: 'Look for "nonce" inside package.',
    plainEnglish: 'If you paste a challenge nonce, we check it matches the nonce in the receipt. That shows this response was made for your session, not copied from an older one. Without a challenge, we only confirm a nonce exists.',
  },
  {
    id: 'signed_only',
    checkId: null,
    swatchClass: 'signed_only',
    label: 'Signed only',
    description: 'Integrity via signature, not independently validated.',
    fieldHint: 'Look for schema, receipt_id, timestamp, prompt/response hashes, identity_claim_hash.',
    plainEnglish: 'These fields are covered by the enclave signature — tampering would break the signature — but the verifier does not re-check them against external data (for example, your original prompt).',
    statusOverride: 'info',
  },
  {
    id: 'ledger',
    checkId: null,
    swatchClass: 'ledger',
    label: 'Public Ledger',
    description: 'Sigstore Rekor transparency log index (browser lookup).',
    fieldHint: 'Look for "log_index" at the root.',
    plainEnglish: 'An optional lookup in Sigstore\'s public transparency log. It shows when this receipt was publicly recorded, separate from the cryptographic checks above.',
    statusOverride: 'ledger',
  },
];

const TRUNCATE_LEN = 52;
const REPORT_HIGHLIGHT_KEYS = ['chipId', 'reportData', 'measurement', 'signature'];
const ROOT_KEY_ORDER = ['package', 'signature', 'pubkey', 'attestation', 'cert_chain', 'runtime_claims_json', 'nonce', 'log_index'];
const DEFAULT_COLLAPSED = ['attestation.certificateChain', 'attestation.report.__other__'];

let wasmReady = false;
let viewMode = 'simple';
let lastReceipt = null;
let lastRenderContext = null;
let expandedPaths = new Set();
let collapsedSections = new Set(DEFAULT_COLLAPSED);
let receiptHoverBound = false;
let receiptLineNum = 0;
let pinnedTopic = null;
let openHelpTopic = null;

const LEGEND_HELP_ICON = `<svg class="verify-advanced__legend-help-icon" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.25"/><path d="M6.2 6.1c.2-1.1 1.1-1.8 2.3-1.8 1.3 0 2.2.7 2.2 1.8 0 .8-.4 1.2-1.1 1.6-.7.4-.9.7-.9 1.3V9.2M8 11.4h.01" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/></svg>`;

const THEME_STORAGE_KEY = 'nexqloud-verify-theme';

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

  const toggle = document.getElementById('theme-toggle');
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
  const toggle = document.getElementById('theme-toggle');
  if (!toggle) return;
  toggle.addEventListener('click', () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    applyTheme(isDark ? 'light' : 'dark');
  });
}

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

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function truncateMiddle(value, max = TRUNCATE_LEN) {
  if (value.length <= max) return value;
  const head = Math.ceil((max - 1) / 2);
  const tail = Math.floor((max - 1) / 2);
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

function isDerivationReceipt(receipt) {
  return receipt?.package?.schema === 'sealed-derivation/1';
}

function topicsForReceipt(receipt) {
  return isDerivationReceipt(receipt) ? DERIVATION_RECEIPT_TOPICS : RECEIPT_TOPICS;
}

function topicForPath(path, receipt = lastReceipt) {
  if (!path) return null;
  if (isDerivationReceipt(receipt)) {
    if (path === 'signature' || path === 'pubkey' || path === 'package') return 'signature';
    if (path.startsWith('cert_chain')) return 'hardware';
    if (path === 'attestation' || path === 'attestation.report') return 'hardware';
    if (path.startsWith('attestation.report.')) {
      const key = path.split('.').pop();
      if (REPORT_HIGHLIGHT_KEYS.includes(key)) return key === 'reportData' ? 'key_binding' : 'hardware';
    }
    if (path === 'nonce') return 'key_binding';
    if (path === 'package.operator_id') return 'derivation_operator';
    if (path === 'package.attestation_hash') return 'derivation_attestation';
    if (path === 'package.tenant_id_hash') return 'derivation_tenant';
    if (path === 'package.key_version') return 'derivation_key_version';
    if (path === 'package.timestamp' || path === 'package.schema') return 'signed_only';
    if (path === 'log_index') return 'ledger';
    return null;
  }
  if (path === 'signature' || path === 'pubkey' || path === 'package') return 'signature';
  if (path.startsWith('cert_chain')) return 'hardware';
  if (path.startsWith('attestation.certificateChain')) return 'unused_chain';
  if (path === 'attestation' || path === 'attestation.report') return 'hardware';
  if (path.startsWith('attestation.report.')) {
    const key = path.split('.').pop();
    if (REPORT_HIGHLIGHT_KEYS.includes(key)) return key === 'reportData' ? 'key_binding' : 'hardware';
  }
  if (path === 'package.nonce') return 'freshness';
  if (path === 'package.enclave_measurement') return 'code_legit';
  if (path === 'package.model_commitment') return 'model_legit';
  if (path === 'package.gpu_policy_hash' || path.startsWith('package.zeroization_cert')) return 'gpu_wiped';
  if (path.startsWith('runtime_claims_json')) return 'key_binding';
  if (path === 'log_index') return 'ledger';
  if (
    path === 'package.schema' ||
    path === 'package.receipt_id' ||
    path === 'package.timestamp' ||
    path === 'package.prompt_hash' ||
    path === 'package.response_hash' ||
    path === 'package.identity_claim_hash'
  ) {
    return 'signed_only';
  }
  return null;
}

function collectTopicsFromReceipt(receipt) {
  const topics = new Set();
  const walk = (value, path) => {
    const topic = topicForPath(path, receipt);
    if (topic) topics.add(topic);
    if (value && typeof value === 'object') {
      if (Array.isArray(value)) {
        value.forEach((item, i) => walk(item, `${path}[${i}]`));
      } else {
        Object.keys(value).forEach((key) => walk(value[key], path ? `${path}.${key}` : key));
      }
    }
  };
  walk(receipt, '');
  return topics;
}

function indent(depth) {
  return '  '.repeat(depth);
}

function fieldAttrs(path) {
  const topic = topicForPath(path);
  let attrs = ` class="receipt-field" data-path="${escapeHtml(path)}"`;
  if (topic) attrs += ` data-topic="${topic}"`;
  if (path === 'package' || path.startsWith('package.')) attrs += ' data-in-package="true"';
  return attrs;
}

function emitLine(innerHtml, depth, topic = null) {
  receiptLineNum += 1;
  const rowClass = topic ? ` receipt-row--topic-${topic}` : '';
  const topicAttr = topic ? ` data-row-topic="${topic}"` : '';
  return `<div class="receipt-row${rowClass}" data-line="${receiptLineNum}"${topicAttr}>
    <span class="receipt-ln">${receiptLineNum}</span>
    <div class="receipt-line" style="--depth:${depth}">${innerHtml}</div>
  </div>`;
}

function rowTopicForPath(path) {
  return topicForPath(path, lastReceipt);
}

function renderPrimitive(value, path) {
  if (value === null) {
    return `<span class="receipt-lit receipt-lit--null">null</span>`;
  }
  if (typeof value === 'boolean') {
    return `<span class="receipt-lit receipt-lit--bool">${value}</span>`;
  }
  if (typeof value === 'number') {
    return `<span class="receipt-lit receipt-lit--num">${value}</span>`;
  }
  if (typeof value === 'string') {
    const expanded = expandedPaths.has(path);
    const isLong = value.length > TRUNCATE_LEN;
    const showTrunc = isLong && !expanded;
    const display = showTrunc ? truncateMiddle(value) : value;
    const attrs = fieldAttrs(path);
    let toggleBtn = '';
    if (isLong) {
      if (expanded) {
        toggleBtn = ` <button type="button" class="receipt-expand" data-collapse-value-path="${escapeHtml(path)}" title="Hide full value">hide</button>`;
      } else {
        toggleBtn = ` <button type="button" class="receipt-expand" data-expand-path="${escapeHtml(path)}" title="Show full value">show</button>`;
      }
    }
    return `<span${attrs}><span class="receipt-lit receipt-lit--str">"${escapeHtml(display)}"</span></span>${toggleBtn}`;
  }
  return escapeHtml(String(value));
}

function renderCollapsedBanner(label, path, depth, meta, topic = null) {
  const isOpen = !collapsedSections.has(path);
  const rowTopic = topic || topicForPath(path);
  return emitLine(`<button type="button" class="receipt-collapse-btn" data-collapse-path="${escapeHtml(path)}" aria-expanded="${isOpen}">
      <span class="receipt-key">"${escapeHtml(label)}"</span><span class="receipt-punct">: </span>
      <span class="receipt-collapse-meta">{ ${escapeHtml(meta)} }</span>
      <span class="receipt-collapse-chevron">${isOpen ? '▾' : '▸'}</span>
    </button>`, depth, rowTopic);
}

function renderObjectEntries(obj, path, depth, keys) {
  const lines = [];
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const childPath = path ? `${path}.${key}` : key;
    const comma = i < keys.length - 1 ? '<span class="receipt-punct">,</span>' : '';
    const keyTopic = topicForPath(childPath);
    const keyAttrs = keyTopic ? ` class="receipt-key receipt-field" data-path="${escapeHtml(childPath)}" data-topic="${keyTopic}"` : ` class="receipt-key"`;

    if (path === 'attestation' && key === 'certificateChain') {
      const isOpen = !collapsedSections.has(childPath);
      lines.push(renderCollapsedBanner('certificateChain', childPath, depth + 1, 'duplicate certs · not verified', 'unused_chain'));
      if (isOpen) {
        lines.push(`<div class="receipt-block receipt-block--nested" data-collapse-body="${escapeHtml(childPath)}">`);
        lines.push(emitLine('<span class="receipt-punct">{</span>', depth + 1, 'unused_chain'));
        lines.push(renderObject(obj[key], childPath, depth + 2));
        lines.push(emitLine(`<span class="receipt-punct">}</span>${comma}`, depth + 1, 'unused_chain'));
        lines.push('</div>');
      }
      continue;
    }

    if (path === 'attestation.report' && key === '__other__') {
      continue;
    }

    const value = obj[key];
    const rowTopic = rowTopicForPath(childPath);
    if (value !== null && typeof value === 'object') {
      lines.push(emitLine(`<span${keyAttrs}>"${escapeHtml(key)}"</span><span class="receipt-punct">: </span><span class="receipt-punct">{</span>`, depth + 1, rowTopic));
      lines.push(renderObject(value, childPath, depth + 2));
      lines.push(emitLine(`<span class="receipt-punct">}</span>${comma}`, depth + 1, rowTopic));
    } else {
      lines.push(emitLine(`<span${keyAttrs}>"${escapeHtml(key)}"</span><span class="receipt-punct">: </span>${renderPrimitive(value, childPath)}${comma}`, depth + 1, rowTopic));
    }
  }
  return lines.join('');
}

function objectKeysForPath(obj, path) {
  if (!path) return ROOT_KEY_ORDER.filter((k) => k in obj);
  if (path === 'attestation') {
    const keys = [];
    if ('report' in obj) keys.push('report');
    if ('certificateChain' in obj) keys.push('certificateChain');
    for (const k of Object.keys(obj)) {
      if (!keys.includes(k)) keys.push(k);
    }
    return keys;
  }
  if (path === 'attestation.report') {
    return REPORT_HIGHLIGHT_KEYS.filter((k) => k in obj);
  }
  return Object.keys(obj);
}

function renderObject(obj, path, depth) {
  if (Array.isArray(obj)) {
    const items = obj.map((item, i) => {
      const childPath = `${path}[${i}]`;
      const inner = item !== null && typeof item === 'object'
        ? `<span class="receipt-punct">{</span>${renderObject(item, childPath, depth + 1)}<span class="receipt-punct">}</span>`
        : renderPrimitive(item, childPath);
      return emitLine(`${inner}<span class="receipt-punct">,</span>`, depth, rowTopicForPath(childPath));
    });
    return items.join('');
  }

  let html = renderObjectEntries(obj, path, depth, objectKeysForPath(obj, path));

  if (path === 'attestation.report') {
    const hiddenKeys = Object.keys(obj).filter((k) => !REPORT_HIGHLIGHT_KEYS.includes(k));
    if (hiddenKeys.length > 0) {
      const hiddenObj = {};
      for (const k of hiddenKeys) hiddenObj[k] = obj[k];
      const otherPath = `${path}.__other__`;
      const isOpen = !collapsedSections.has(otherPath);
      const comma = '';
      html += renderCollapsedBanner('…', otherPath, depth + 1, `${hiddenKeys.length} other report fields`, 'hardware');
      if (isOpen) {
        html += `<div class="receipt-block receipt-block--nested" data-collapse-body="${escapeHtml(otherPath)}">`;
        html += emitLine('<span class="receipt-punct">{</span>', depth + 1, 'hardware');
        html += renderObjectEntries(hiddenObj, otherPath, depth + 2, Object.keys(hiddenObj));
        html += emitLine(`<span class="receipt-punct">}</span>${comma}`, depth + 1, 'hardware');
        html += '</div>';
      }
    }
  }

  return html;
}

function renderReceiptDocument(receipt) {
  receiptLineNum = 0;
  return `<div class="receipt-doc">${emitLine('<span class="receipt-punct">{</span>', 0)}${renderObject(receipt, '', 0)}${emitLine('<span class="receipt-punct">}</span>', 0)}</div>`;
}

function resetExplorerState() {
  expandedPaths = new Set();
  collapsedSections = new Set(DEFAULT_COLLAPSED);
  pinnedTopic = null;
  openHelpTopic = null;
}

function closeLegendHelp() {
  openHelpTopic = null;
  document.querySelectorAll('.verify-advanced__legend-help-popup').forEach((el) => {
    el.hidden = true;
  });
  document.querySelectorAll('.verify-advanced__legend-help').forEach((btn) => {
    btn.setAttribute('aria-expanded', 'false');
  });
}

function toggleLegendHelp(topicId) {
  if (openHelpTopic === topicId) {
    closeLegendHelp();
    return;
  }
  closeLegendHelp();
  openHelpTopic = topicId;
  const popup = document.querySelector(`.verify-advanced__legend-help-popup[data-help-topic="${topicId}"]`);
  const btn = document.querySelector(`.verify-advanced__legend-help[data-help-topic="${topicId}"]`);
  if (popup) popup.hidden = false;
  if (btn) btn.setAttribute('aria-expanded', 'true');
}

function checkStatusForTopic(topic, checksById, challengeHex) {
  if (topic.statusOverride) return topic.statusOverride;
  if (!topic.checkId) return 'info';
  const check = checksById[topic.checkId];
  if (!check) return 'info';
  if (topic.checkId === 'freshness' && challengeHex === '') return 'skipped';
  return check.ok ? 'pass' : 'fail';
}

function statusLabel(status) {
  switch (status) {
    case 'pass': return 'Pass';
    case 'fail': return 'Fail';
    case 'skipped': return 'Skipped';
    case 'ledger': return 'Rekor';
    default: return 'Info';
  }
}

function highlightLegendTopic(topicId) {
  document.querySelectorAll('.verify-advanced__legend-item').forEach((el) => {
    const id = el.dataset.topic;
    el.classList.toggle('verify-advanced__legend-item--selected', pinnedTopic === id);
    el.classList.toggle('verify-advanced__legend-item--linked', Boolean(topicId && topicId === id && pinnedTopic !== id));
  });
}

function topicMeta(topicId) {
  const topics = topicsForReceipt(lastReceipt);
  return topics.find((t) => t.id === topicId);
}

function rowMatchesTopic(row, topicId) {
  if (!topicId) return true;
  if (topicId === 'signature') {
    return row.querySelector('[data-topic="signature"], [data-in-package="true"]');
  }
  if (row.dataset.rowTopic === topicId) return true;
  return row.querySelector(`[data-topic="${topicId}"]`);
}

function fieldsForTopic(jsonEl, topicId) {
  if (topicId === 'signature') {
    return jsonEl.querySelectorAll('[data-topic="signature"], [data-in-package="true"]');
  }
  return jsonEl.querySelectorAll(`[data-topic="${topicId}"]`);
}

function updateFocusHint(topicId) {
  const hint = document.getElementById('advanced-focus-hint');
  if (!hint) return;
  if (!topicId) {
    hint.hidden = true;
    hint.textContent = '';
    return;
  }
  const meta = topicMeta(topicId);
  hint.hidden = false;
  hint.textContent = meta?.fieldHint || '';
}

function applyTopicFocus(topicId) {
  const jsonEl = document.getElementById('advanced-json');
  const doc = jsonEl.querySelector('.receipt-doc');
  doc?.classList.toggle('receipt-doc--focused', Boolean(topicId));
  if (doc) {
    if (topicId) doc.dataset.focusTopic = topicId;
    else delete doc.dataset.focusTopic;
  }

  jsonEl.querySelectorAll('.receipt-row').forEach((row) => {
    const match = rowMatchesTopic(row, topicId);
    row.classList.toggle('receipt-row--match', Boolean(topicId && match));
    row.classList.toggle('receipt-row--dimmed', Boolean(topicId && !match));
  });

  jsonEl.querySelectorAll('.receipt-field--pinned').forEach((el) => {
    el.classList.remove('receipt-field--pinned');
  });

  if (!topicId) return;

  const fields = fieldsForTopic(jsonEl, topicId);
  fields.forEach((el) => {
    el.classList.add('receipt-field--pinned');
  });
}

function focusTopic(topicId) {
  pinnedTopic = pinnedTopic === topicId ? null : topicId;
  highlightLegendTopic(null);
  updateFocusHint(pinnedTopic);
  applyTopicFocus(pinnedTopic);

  if (!pinnedTopic) return;

  const jsonEl = document.getElementById('advanced-json');
  const first = fieldsForTopic(jsonEl, pinnedTopic)[0];
  if (first) {
    const row = first.closest('.receipt-row');
    (row || first).scrollIntoView({ block: 'center', behavior: 'smooth' });
  }
}

function renderAdvancedLegend(checksById, challengeHex, presentTopicIds, receipt) {
  const legend = document.getElementById('advanced-legend');
  legend.innerHTML = '';

  for (const topic of topicsForReceipt(receipt)) {
    if (!presentTopicIds.has(topic.id)) continue;

    const status = checkStatusForTopic(topic, checksById, challengeHex);
    const li = document.createElement('li');
    const item = document.createElement('div');
    item.className = 'verify-advanced__legend-item';
    item.dataset.topic = topic.id;
    item.innerHTML = `
      <div class="verify-advanced__legend-head">
        <span class="verify-advanced__legend-swatch verify-advanced__legend-swatch--${topic.swatchClass}"></span>
        <span class="verify-advanced__legend-label">${topic.label}</span>
        <button type="button" class="verify-advanced__legend-help" data-help-topic="${topic.id}" aria-expanded="false" aria-label="Explain ${topic.label}">${LEGEND_HELP_ICON}</button>
        <span class="verify-advanced__legend-status verify-advanced__legend-status--${status}">${statusLabel(status)}</span>
      </div>
      <p class="verify-advanced__legend-desc">${topic.description}</p>
      <div class="verify-advanced__legend-help-popup" data-help-topic="${topic.id}" hidden>${escapeHtml(topic.plainEnglish || topic.description)}</div>
    `;
    li.appendChild(item);
    legend.appendChild(li);
  }
}

function renderAdvancedExplorer(receipt, context) {
  const { checksById, challengeHex } = context;
  closeLegendHelp();
  const jsonEl = document.getElementById('advanced-json');
  jsonEl.innerHTML = renderReceiptDocument(receipt);
  renderAdvancedLegend(checksById, challengeHex, collectTopicsFromReceipt(receipt), receipt);
  highlightLegendTopic(null);
  updateFocusHint(pinnedTopic);
  applyTopicFocus(pinnedTopic);
  bindReceiptExplorerEvents(jsonEl);
}

function scrollToTopic(topicId) {
  focusTopic(topicId);
}

function bindReceiptExplorerEvents(jsonEl) {
  if (receiptHoverBound) return;
  receiptHoverBound = true;

  jsonEl.addEventListener('mouseover', (e) => {
    const field = e.target.closest('[data-topic]');
    if (field) highlightLegendTopic(field.dataset.topic);
  });

  jsonEl.addEventListener('mouseout', (e) => {
    const next = e.relatedTarget;
    if (!next || !jsonEl.contains(next) || !next.closest?.('[data-topic]')) {
      highlightLegendTopic(null);
    }
  });

  jsonEl.addEventListener('click', (e) => {
    const expandBtn = e.target.closest('[data-expand-path]');
    if (expandBtn) {
      e.preventDefault();
      expandedPaths.add(expandBtn.dataset.expandPath);
      if (lastReceipt && lastRenderContext) renderAdvancedExplorer(lastReceipt, lastRenderContext);
      return;
    }

    const collapseValueBtn = e.target.closest('[data-collapse-value-path]');
    if (collapseValueBtn) {
      e.preventDefault();
      expandedPaths.delete(collapseValueBtn.dataset.collapseValuePath);
      if (lastReceipt && lastRenderContext) renderAdvancedExplorer(lastReceipt, lastRenderContext);
      return;
    }

    const collapseBtn = e.target.closest('[data-collapse-path]');
    if (collapseBtn) {
      e.preventDefault();
      const path = collapseBtn.dataset.collapsePath;
      if (collapsedSections.has(path)) collapsedSections.delete(path);
      else collapsedSections.add(path);
      if (lastReceipt && lastRenderContext) renderAdvancedExplorer(lastReceipt, lastRenderContext);
      return;
    }

    if (!e.target.closest('[data-topic], .receipt-expand, .receipt-collapse-btn')) {
      pinnedTopic = null;
      highlightLegendTopic(null);
      updateFocusHint(null);
      applyTopicFocus(null);
    }
  });

  document.getElementById('advanced-legend').addEventListener('click', (e) => {
    if (e.target.closest('.verify-advanced__legend-help')) {
      e.stopPropagation();
      const btn = e.target.closest('.verify-advanced__legend-help');
      toggleLegendHelp(btn.dataset.helpTopic);
      return;
    }
    if (e.target.closest('.verify-advanced__legend-help-popup')) return;
    const item = e.target.closest('[data-topic]');
    if (item) focusTopic(item.dataset.topic);
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('.verify-advanced__legend-help, .verify-advanced__legend-help-popup')) {
      closeLegendHelp();
    }
  });
}

function setViewMode(mode) {
  viewMode = mode;
  const simplePanel = document.getElementById('simple-panel');
  const advancedSection = document.getElementById('advanced-section');
  const simpleBtn = document.getElementById('mode-simple');
  const advancedBtn = document.getElementById('mode-advanced');

  simpleBtn.classList.toggle('verify-mode__btn--active', mode === 'simple');
  advancedBtn.classList.toggle('verify-mode__btn--active', mode === 'advanced');
  simpleBtn.setAttribute('aria-pressed', mode === 'simple' ? 'true' : 'false');
  advancedBtn.setAttribute('aria-pressed', mode === 'advanced' ? 'true' : 'false');

  simplePanel.hidden = mode !== 'simple';
  advancedSection.hidden = mode !== 'advanced';

  if (mode === 'advanced' && lastReceipt && lastRenderContext) {
    renderAdvancedExplorer(lastReceipt, lastRenderContext);
  }
}

function setupViewMode() {
  document.getElementById('mode-simple').addEventListener('click', () => setViewMode('simple'));
  document.getElementById('mode-advanced').addEventListener('click', () => setViewMode('advanced'));
}

function renderFreshnessCheck(check, challengeHex) {
  const li = document.createElement('li');
  const hashDisplay = check.hash
    ? `<span class="verify-check__hash">(${truncateHex(check.hash)})</span>`
    : '';

  let stateClass;
  let icon;
  let label;
  let detail;

  if (challengeHex === '') {
    stateClass = 'verify-check--skipped';
    icon = ICON_SKIPPED;
    label = 'Freshness (Skipped)';
    detail = 'Nonce present, but no challenge supplied to verify freshness';
  } else if (check.ok) {
    stateClass = 'verify-check--pass';
    icon = ICON_PASS;
    label = CHECK_LABELS.freshness;
    detail = 'nonce matches challenge';
  } else {
    stateClass = 'verify-check--fail';
    icon = ICON_FAIL;
    label = CHECK_LABELS.freshness;
    detail = check.detail || 'nonce does not match challenge';
  }

  li.className = `verify-check ${stateClass}`;
  li.innerHTML = `
    ${icon}
    <div class="verify-check__body">
      <div class="verify-check__label">
        ${label}
        ${hashDisplay}
      </div>
      <div class="verify-check__detail">${detail}</div>
    </div>
  `;
  return li;
}

function renderCheck(check, challengeHex = '') {
  if (check.id === 'freshness') {
    return renderFreshnessCheck(check, challengeHex);
  }

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

async function runWasmVerify(receiptJSON) {
  if (!wasmReady) throw new Error('Wasm module not loaded');

  const challenge = document.getElementById('challenge-input').value.trim();
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
    wasmResult = await runWasmVerify(text);
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
  const challenge = document.getElementById('challenge-input').value.trim();
  lastReceipt = receipt;
  renderResults(wasmResult, rekorInfo, rekorError, challenge);
}

function renderResults(result, rekorInfo, rekorError = null, challengeHex = '') {
  const results = document.getElementById('results');
  const checklist = document.getElementById('checklist');
  const badge = document.getElementById('overall-badge');
  const meta = document.getElementById('receipt-meta');

  results.hidden = false;
  checklist.innerHTML = '';

  for (const check of result.checks) {
    checklist.appendChild(renderCheck(check, challengeHex));
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
  } else if (result.schema === 'sealed-derivation/1' || isDerivationReceipt(lastReceipt)) {
    const pkg = lastReceipt?.package || {};
    const parts = [];
    if (result.operator_id || pkg.operator_id) {
      parts.push(`operator_id: ${result.operator_id || pkg.operator_id}`);
    }
    if (pkg.key_version !== undefined && pkg.key_version !== null) {
      parts.push(`key_version: ${pkg.key_version}`);
    }
    if (pkg.attestation_hash) {
      parts.push(`attestation_hash: ${truncateHex(pkg.attestation_hash)}`);
    }
    if (pkg.tenant_id_hash) {
      parts.push(`tenant_id_hash: ${truncateHex(pkg.tenant_id_hash)}`);
    }
    meta.textContent = parts.join(' · ');
  }

  const checksById = Object.fromEntries(result.checks.map((c) => [c.id, c]));
  lastRenderContext = { checksById, challengeHex, result, rekorInfo, rekorError };
  resetExplorerState();

  if (viewMode === 'advanced') {
    renderAdvancedExplorer(lastReceipt, lastRenderContext);
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
  setupThemeToggle();
  setupDropZone();
  setupViewMode();
  setStatus('Loading WebAssembly verifier…');
  try {
    await initWasm();
    hideStatus();
  } catch (err) {
    setStatus(`Failed to load Wasm: ${err.message}`, false);
  }
});
