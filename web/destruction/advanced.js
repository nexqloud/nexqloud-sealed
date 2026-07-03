const PROOF_TOPICS = [
  {
    id: 'signature',
    checkId: 'proof_signature',
    swatchClass: 'signature',
    label: 'Proof Signature',
    description: 'Substrate Ed25519 signature over the canonical proof package.',
    fieldHint: 'Look for "signature", "pubkey", and fields inside "package".',
    plainEnglish: 'The federation substrate signed the unified destruction proof. We verify that signature with the public key in the proof.',
  },
  {
    id: 'quorum',
    checkId: 'registry_quorum',
    swatchClass: 'derivation',
    label: 'Registry Quorum',
    description: 'Operator set committed in the proof and matched to receipts.',
    fieldHint: 'Look for "quorum" inside package.',
    plainEnglish: 'Lists which federation operators must participate in this erasure. The verifier confirms receipt operators match this quorum.',
  },
  {
    id: 'merkle',
    checkId: 'merkle_root',
    swatchClass: 'unused',
    label: 'Unified Merkle Root',
    description: 'Merkle root over canonical operator receipt leaves.',
    fieldHint: 'Look for "merkle_root" inside package.',
    plainEnglish: 'Binds every operator receipt into one federated root. Receipt leaves must recompute to this value.',
  },
  {
    id: 'destruction',
    checkId: null,
    swatchClass: 'signed_only',
    label: 'Destruction ID',
    description: 'Unique identifier for this federated erasure event.',
    fieldHint: 'Look for "destruction_id" inside package.',
    plainEnglish: 'Correlates the unified proof with each operator destruction receipt.',
    statusOverride: 'info',
  },
  {
    id: 'tenant',
    checkId: null,
    swatchClass: 'derivation',
    label: 'Tenant Hash',
    description: 'SHA-256 commitment to the tenant identifier.',
    fieldHint: 'Look for "tenant_id_hash" inside package.',
    plainEnglish: 'Shows which tenant context this erasure belongs to without revealing the raw tenant ID.',
    statusOverride: 'info',
  },
  {
    id: 'signed_only',
    checkId: null,
    swatchClass: 'signed_only',
    label: 'Signed only',
    description: 'Integrity via signature, not independently validated.',
    fieldHint: 'Look for schema and timestamp inside package.',
    plainEnglish: 'These fields are covered by the substrate signature but are not checked against external catalogs.',
    statusOverride: 'info',
  },
  {
    id: 'ledger',
    checkId: 'rekor_log_index',
    swatchClass: 'ledger',
    label: 'Public Ledger',
    description: 'Sigstore Rekor transparency log index.',
    fieldHint: 'Look for "log_index" at the root.',
    plainEnglish: 'Optional lookup in Sigstore\'s public transparency log for when this proof was recorded.',
    statusOverride: 'ledger',
  },
];

const RECEIPT_TOPICS = [
  {
    id: 'signature',
    checkId: 'signature_valid',
    swatchClass: 'signature',
    label: 'Signature Valid',
    description: 'Ed25519 signature over the RFC 8785 canonical package.',
    fieldHint: 'Look for "signature", "pubkey", and all fields inside "package".',
    plainEnglish: 'The operator signed destruction claims with its enclave private key. We verify that signature using the public key in the receipt.',
  },
  {
    id: 'hardware',
    checkId: 'hardware_genuine',
    swatchClass: 'hardware',
    label: 'Hardware Genuine',
    description: 'AMD SEV-SNP report plus cert_chain (VCEK → ASK → ARK).',
    fieldHint: 'Look for "cert_chain" and key fields inside "attestation.report".',
    plainEnglish: 'Proves the destruction attestation came from real AMD silicon with a validated certificate chain.',
  },
  {
    id: 'key_binding',
    checkId: 'key_binding',
    swatchClass: 'key_binding',
    label: 'Key Bound to Silicon',
    description: 'Links pubkey + nonce into hardware attestation reportData or Azure user-data.',
    fieldHint: 'Look for "reportData", root "nonce", and "runtime_claims_json".',
    plainEnglish: 'Confirms the signing key was bound into the hardware attestation for this destruction.',
  },
  {
    id: 'attestation_hash',
    checkId: 'destruction_attestation_hash',
    swatchClass: 'derivation',
    label: 'Attestation Hash',
    description: 'SHA-256 of attestation bytes committed in the signed package.',
    fieldHint: 'Look for "attestation_hash" inside package.',
    plainEnglish: 'Binds the signed package to the exact hardware attestation blob in the receipt.',
  },
  {
    id: 'zeroization',
    checkId: 'zeroization_evidence',
    swatchClass: 'gpu_wiped',
    label: 'Zeroization Evidence',
    description: 'Wrap erasure, ciphertext overwrite, chip contribution, and salt rotation flags.',
    fieldHint: 'Look for "zeroization_evidence" inside package.',
    plainEnglish: 'Documents that sealing material was destroyed: wrap hash erased, ciphertext overwritten, chip contribution destroyed, salt rotated.',
  },
  {
    id: 'salt_epoch',
    checkId: 'salt_epoch',
    swatchClass: 'freshness',
    label: 'Salt Epoch',
    description: 'Federation salt epoch after anti-rollback rotation.',
    fieldHint: 'Look for "salt_epoch" inside package.',
    plainEnglish: 'Records the federation salt version active when this operator performed erasure.',
  },
  {
    id: 'tenant',
    checkId: 'destruction_tenant_hash',
    swatchClass: 'derivation',
    label: 'Tenant Hash',
    description: 'SHA-256 commitment to the tenant identifier.',
    fieldHint: 'Look for "tenant_id_hash" inside package.',
    plainEnglish: 'Shows which tenant federation context this destruction receipt belongs to.',
  },
  {
    id: 'freshness',
    checkId: 'freshness',
    swatchClass: 'freshness',
    label: 'Freshness',
    description: 'Session nonce bound into the destruction receipt.',
    fieldHint: 'Look for root-level "nonce".',
    plainEnglish: 'The coordinator-issued nonce ties this receipt to a specific deletion request.',
  },
  {
    id: 'operator',
    checkIdPrefix: 'destruction_operator_id:',
    swatchClass: 'derivation',
    label: 'Operator ID',
    description: 'Federated operator that performed this destruction.',
    fieldHint: 'Look for "operator_id" inside package.',
    plainEnglish: 'Identifies which federation operator (for example operator-a) created this receipt.',
  },
  {
    id: 'signed_only',
    checkId: null,
    swatchClass: 'signed_only',
    label: 'Signed only',
    description: 'Integrity via signature, not independently validated.',
    fieldHint: 'Look for schema and timestamp inside package.',
    plainEnglish: 'These fields are covered by the operator signature but are not independently validated.',
    statusOverride: 'info',
  },
];

const REPORT_HIGHLIGHT_KEYS = ['chipId', 'reportData', 'measurement', 'signature'];

function isProofDocument(doc) {
  const schema = doc?.package?.schema;
  return schema === 'sealed-destruction-proof/1';
}

function topicForProofPath(path) {
  if (!path) return null;
  if (path === 'signature' || path === 'pubkey' || path === 'package') return 'signature';
  if (path === 'package.quorum') return 'quorum';
  if (path === 'package.merkle_root') return 'merkle';
  if (path === 'package.destruction_id') return 'destruction';
  if (path === 'package.tenant_id_hash') return 'tenant';
  if (path === 'log_index') return 'ledger';
  if (path === 'package.schema' || path === 'package.at') return 'signed_only';
  return null;
}

function topicForReceiptPath(path) {
  if (!path) return null;
  if (path === 'signature' || path === 'pubkey' || path === 'package') return 'signature';
  if (path.startsWith('cert_chain')) return 'hardware';
  if (path === 'attestation' || path === 'attestation.report') return 'hardware';
  if (path.startsWith('attestation.report.')) {
    const key = path.split('.').pop();
    if (REPORT_HIGHLIGHT_KEYS.includes(key)) return key === 'reportData' ? 'key_binding' : 'hardware';
  }
  if (path === 'nonce' || path.startsWith('runtime_claims_json')) return 'key_binding';
  if (path === 'package.attestation_hash') return 'attestation_hash';
  if (path === 'package.zeroization_evidence' || path.startsWith('package.zeroization_evidence.')) return 'zeroization';
  if (path === 'package.salt_epoch') return 'salt_epoch';
  if (path === 'package.tenant_id_hash') return 'tenant';
  if (path === 'package.operator_id') return 'operator';
  if (path === 'package.schema' || path === 'package.timestamp') return 'signed_only';
  return null;
}

function partitionChecks(checks) {
  const proofChecks = {};
  const receiptChecks = [];
  let bucket = [];

  for (const check of checks) {
    if (['registry_quorum', 'proof_signature', 'merkle_root', 'rekor_log_index'].includes(check.id)) {
      proofChecks[check.id] = check;
      continue;
    }
    bucket.push(check);
    if (check.id.startsWith('destruction_operator_id:')) {
      receiptChecks.push(Object.fromEntries(bucket.map((c) => [c.id, c])));
      bucket = [];
    }
  }

  return { proofChecks, receiptChecks };
}

function initDestructionAdvanced() {
  const explorer = ReceiptExplorer.create({
    getTopics(doc) {
      return isProofDocument(doc) ? PROOF_TOPICS : RECEIPT_TOPICS;
    },
    topicForPath(path, doc) {
      return isProofDocument(doc) ? topicForProofPath(path) : topicForReceiptPath(path);
    },
  });

  let viewMode = 'simple';
  let advancedDocs = [];
  let activeDocId = 'proof';
  let lastBundle = null;

  const elements = {
    json: document.getElementById('advanced-json'),
    legend: document.getElementById('advanced-legend'),
    focusHint: document.getElementById('advanced-focus-hint'),
    fileTabs: document.getElementById('advanced-file-tabs'),
  };

  explorer.bindEvents(elements);

  function buildAdvancedDocs(proof, proofLabel, receiptEntries, result) {
    const { proofChecks, receiptChecks } = partitionChecks(result.checks);
    const docs = [
      {
        id: 'proof',
        label: proofLabel || 'Unified proof',
        document: proof,
        checksById: proofChecks,
      },
    ];

    receiptEntries.forEach((entry, index) => {
      const operator = entry.data?.package?.operator_id || `receipt-${index + 1}`;
      docs.push({
        id: `receipt-${index}`,
        label: entry.file?.name || operator,
        document: entry.data,
        checksById: receiptChecks[index] || {},
      });
    });

    return docs;
  }

  function renderFileTabs() {
    if (!elements.fileTabs) return;
    elements.fileTabs.innerHTML = '';
    for (const doc of advancedDocs) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'verify-advanced__file-tab';
      btn.dataset.docId = doc.id;
      btn.setAttribute('role', 'tab');
      btn.setAttribute('aria-selected', doc.id === activeDocId ? 'true' : 'false');
      if (doc.id === activeDocId) btn.classList.add('verify-advanced__file-tab--active');
      btn.textContent = doc.label;
      btn.addEventListener('click', () => {
        activeDocId = doc.id;
        explorer.resetState();
        renderFileTabs();
        renderActiveDoc();
      });
      elements.fileTabs.appendChild(btn);
    }
  }

  function renderActiveDoc() {
    const doc = advancedDocs.find((d) => d.id === activeDocId) || advancedDocs[0];
    if (!doc) return;
    explorer.render(doc.document, {
      checksById: doc.checksById,
      challengeHex: '',
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

    if (mode === 'advanced' && lastBundle) {
      updateAdvanced(lastBundle.proof, lastBundle.proofLabel, lastBundle.receiptEntries, lastBundle.result);
    }
  }

  function updateAdvanced(proof, proofLabel, receiptEntries, result) {
    lastBundle = { proof, proofLabel, receiptEntries, result };
    advancedDocs = buildAdvancedDocs(proof, proofLabel, receiptEntries, result);
    if (!advancedDocs.some((d) => d.id === activeDocId)) {
      activeDocId = 'proof';
    }
    if (viewMode === 'advanced') {
      renderFileTabs();
      renderActiveDoc();
    }
  }

  function resetAdvanced() {
    lastBundle = null;
    advancedDocs = [];
    activeDocId = 'proof';
    explorer.resetState();
    if (elements.fileTabs) elements.fileTabs.innerHTML = '';
    if (elements.json) elements.json.innerHTML = '';
    if (elements.legend) elements.legend.innerHTML = '';
    if (elements.focusHint) {
      elements.focusHint.hidden = true;
      elements.focusHint.textContent = '';
    }
  }

  document.getElementById('mode-simple').addEventListener('click', () => setViewMode('simple'));
  document.getElementById('mode-advanced').addEventListener('click', () => setViewMode('advanced'));

  return {
    updateAdvanced,
    resetAdvanced,
    setViewMode,
  };
}
