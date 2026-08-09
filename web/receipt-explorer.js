(function (global) {
  const LEGEND_HELP_ICON = `<svg class="verify-advanced__legend-help-icon" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.25"/><path d="M6.2 6.1c.2-1.1 1.1-1.8 2.3-1.8 1.3 0 2.2.7 2.2 1.8 0 .8-.4 1.2-1.1 1.6-.7.4-.9.7-.9 1.3V9.2M8 11.4h.01" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/></svg>`;

  function defaultEscapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function createReceiptExplorer(userOptions) {
    const options = {
      truncateLen: 52,
      reportHighlightKeys: ['chipId', 'reportData', 'measurement', 'signature'],
      rootKeyOrder: ['package', 'signature', 'pubkey', 'attestation', 'cert_chain', 'nonce', 'log_index'],
      defaultCollapsed: ['attestation.report.__other__'],
      escapeHtml: defaultEscapeHtml,
      ...userOptions,
    };

    let expandedPaths = new Set();
    let collapsedSections = new Set(options.defaultCollapsed);
    let receiptLineNum = 0;
    let pinnedTopic = null;
    let openHelpTopic = null;
    let currentDocument = null;
    let currentContext = null;
    let elements = null;
    let eventsBound = false;

    function resetState() {
      expandedPaths = new Set();
      collapsedSections = new Set(options.defaultCollapsed);
      pinnedTopic = null;
      openHelpTopic = null;
    }

    function truncateMiddle(value, max = options.truncateLen) {
      if (value.length <= max) return value;
      const head = Math.ceil((max - 1) / 2);
      const tail = Math.floor((max - 1) / 2);
      return `${value.slice(0, head)}…${value.slice(-tail)}`;
    }

    function topicForPath(path) {
      return options.topicForPath(path, currentDocument, currentContext);
    }

    function topicsForDocument() {
      return options.getTopics(currentDocument, currentContext);
    }

    function collectTopicsFromDocument(doc) {
      const topics = new Set();
      const walk = (value, path) => {
        const topic = options.topicForPath(path, doc, currentContext);
        if (topic) topics.add(topic);
        if (value && typeof value === 'object') {
          if (Array.isArray(value)) {
            value.forEach((item, i) => walk(item, `${path}[${i}]`));
          } else {
            Object.keys(value).forEach((key) => walk(value[key], path ? `${path}.${key}` : key));
          }
        }
      };
      walk(doc, '');
      return topics;
    }

    function fieldAttrs(path) {
      const topic = topicForPath(path);
      let attrs = ` class="receipt-field" data-path="${options.escapeHtml(path)}"`;
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
        const isLong = value.length > options.truncateLen;
        const showTrunc = isLong && !expanded;
        const display = showTrunc ? truncateMiddle(value) : value;
        const attrs = fieldAttrs(path);
        let toggleBtn = '';
        if (isLong) {
          if (expanded) {
            toggleBtn = ` <button type="button" class="receipt-expand" data-collapse-value-path="${options.escapeHtml(path)}" title="Hide full value">hide</button>`;
          } else {
            toggleBtn = ` <button type="button" class="receipt-expand" data-expand-path="${options.escapeHtml(path)}" title="Show full value">show</button>`;
          }
        }
        return `<span${attrs}><span class="receipt-lit receipt-lit--str">"${options.escapeHtml(display)}"</span></span>${toggleBtn}`;
      }
      return options.escapeHtml(String(value));
    }

    function renderCollapsedBanner(label, path, depth, meta, topic = null) {
      const isOpen = !collapsedSections.has(path);
      const rowTopic = topic || topicForPath(path);
      return emitLine(`<button type="button" class="receipt-collapse-btn" data-collapse-path="${options.escapeHtml(path)}" aria-expanded="${isOpen}">
      <span class="receipt-key">"${options.escapeHtml(label)}"</span><span class="receipt-punct">: </span>
      <span class="receipt-collapse-meta">{ ${options.escapeHtml(meta)} }</span>
      <span class="receipt-collapse-chevron">${isOpen ? '▾' : '▸'}</span>
    </button>`, depth, rowTopic);
    }

    function objectKeysForPath(obj, path) {
      if (!path) return options.rootKeyOrder.filter((k) => k in obj);
      if (path === 'attestation') {
        return ['report'].filter((k) => k in obj);
      }
      if (path === 'attestation.report') {
        return options.reportHighlightKeys.filter((k) => k in obj);
      }
      return Object.keys(obj);
    }

    function renderObjectEntries(obj, path, depth, keys) {
      const lines = [];
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        const childPath = path ? `${path}.${key}` : key;
        const comma = i < keys.length - 1 ? '<span class="receipt-punct">,</span>' : '';
        const keyTopic = topicForPath(childPath);
        const keyAttrs = keyTopic
          ? ` class="receipt-key receipt-field" data-path="${options.escapeHtml(childPath)}" data-topic="${keyTopic}"`
          : ' class="receipt-key"';

        if (path === 'attestation.report' && key === '__other__') {
          continue;
        }

        const value = obj[key];
        const rowTopic = topicForPath(childPath);
        if (value !== null && typeof value === 'object') {
          lines.push(emitLine(`<span${keyAttrs}>"${options.escapeHtml(key)}"</span><span class="receipt-punct">: </span><span class="receipt-punct">{</span>`, depth + 1, rowTopic));
          lines.push(renderObject(value, childPath, depth + 2));
          lines.push(emitLine(`<span class="receipt-punct">}</span>${comma}`, depth + 1, rowTopic));
        } else {
          lines.push(emitLine(`<span${keyAttrs}>"${options.escapeHtml(key)}"</span><span class="receipt-punct">: </span>${renderPrimitive(value, childPath)}${comma}`, depth + 1, rowTopic));
        }
      }
      return lines.join('');
    }

    function renderObject(obj, path, depth) {
      if (Array.isArray(obj)) {
        const items = obj.map((item, i) => {
          const childPath = `${path}[${i}]`;
          const inner = item !== null && typeof item === 'object'
            ? `<span class="receipt-punct">{</span>${renderObject(item, childPath, depth + 1)}<span class="receipt-punct">}</span>`
            : renderPrimitive(item, childPath);
          return emitLine(`${inner}<span class="receipt-punct">,</span>`, depth, topicForPath(childPath));
        });
        return items.join('');
      }

      let html = renderObjectEntries(obj, path, depth, objectKeysForPath(obj, path));

      if (path === 'attestation.report') {
        const hiddenKeys = Object.keys(obj).filter((k) => !options.reportHighlightKeys.includes(k));
        if (hiddenKeys.length > 0) {
          const hiddenObj = {};
          for (const k of hiddenKeys) hiddenObj[k] = obj[k];
          const otherPath = `${path}.__other__`;
          const isOpen = !collapsedSections.has(otherPath);
          html += renderCollapsedBanner('…', otherPath, depth + 1, `${hiddenKeys.length} other report fields`, 'hardware');
          if (isOpen) {
            html += `<div class="receipt-block receipt-block--nested" data-collapse-body="${options.escapeHtml(otherPath)}">`;
            html += emitLine('<span class="receipt-punct">{</span>', depth + 1, 'hardware');
            html += renderObjectEntries(hiddenObj, otherPath, depth + 2, Object.keys(hiddenObj));
            html += emitLine('<span class="receipt-punct">}</span>', depth + 1, 'hardware');
            html += '</div>';
          }
        }
      }

      return html;
    }

    function renderReceiptDocument(doc) {
      receiptLineNum = 0;
      return `<div class="receipt-doc">${emitLine('<span class="receipt-punct">{</span>', 0)}${renderObject(doc, '', 0)}${emitLine('<span class="receipt-punct">}</span>', 0)}</div>`;
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

    function checkStatusForTopic(topic) {
      if (topic.statusOverride) return topic.statusOverride;
      if (!topic.checkId && !topic.checkIdPrefix) return 'info';
      const checksById = currentContext?.checksById || {};
      let check = topic.checkId ? checksById[topic.checkId] : null;
      if (!check && topic.checkIdPrefix) {
        check = Object.values(checksById).find((c) => c.id && c.id.startsWith(topic.checkIdPrefix));
      }
      if (!check) return 'info';
      if (topic.checkId === 'freshness' && !currentContext?.challengeHex) return 'skipped';
      return check.ok ? 'pass' : 'fail';
    }

    function closeLegendHelp() {
      openHelpTopic = null;
      if (!elements?.legend) return;
      elements.legend.querySelectorAll('.verify-advanced__legend-help-popup').forEach((el) => {
        el.hidden = true;
      });
      elements.legend.querySelectorAll('.verify-advanced__legend-help').forEach((btn) => {
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
      const popup = elements.legend.querySelector(`.verify-advanced__legend-help-popup[data-help-topic="${topicId}"]`);
      const btn = elements.legend.querySelector(`.verify-advanced__legend-help[data-help-topic="${topicId}"]`);
      if (popup) popup.hidden = false;
      if (btn) btn.setAttribute('aria-expanded', 'true');
    }

    function highlightLegendTopic(topicId) {
      if (!elements?.legend) return;
      elements.legend.querySelectorAll('.verify-advanced__legend-item').forEach((el) => {
        const id = el.dataset.topic;
        el.classList.toggle('verify-advanced__legend-item--selected', pinnedTopic === id);
        el.classList.toggle('verify-advanced__legend-item--linked', Boolean(topicId && topicId === id && pinnedTopic !== id));
      });
    }

    function topicMeta(topicId) {
      return topicsForDocument().find((t) => t.id === topicId);
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
      if (!elements?.focusHint) return;
      if (!topicId) {
        elements.focusHint.hidden = true;
        elements.focusHint.textContent = '';
        return;
      }
      const meta = topicMeta(topicId);
      elements.focusHint.hidden = false;
      elements.focusHint.textContent = meta?.fieldHint || '';
    }

    function applyTopicFocus(topicId) {
      if (!elements?.json) return;
      const jsonEl = elements.json;
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
      fieldsForTopic(jsonEl, topicId).forEach((el) => {
        el.classList.add('receipt-field--pinned');
      });
    }

    function focusTopic(topicId) {
      pinnedTopic = pinnedTopic === topicId ? null : topicId;
      highlightLegendTopic(null);
      updateFocusHint(pinnedTopic);
      applyTopicFocus(pinnedTopic);

      if (!pinnedTopic || !elements?.json) return;
      const first = fieldsForTopic(elements.json, pinnedTopic)[0];
      if (first) {
        const row = first.closest('.receipt-row');
        (row || first).scrollIntoView({ block: 'center', behavior: 'smooth' });
      }
    }

    function renderLegend() {
      if (!elements?.legend) return;
      const legend = elements.legend;
      legend.innerHTML = '';
      const presentTopicIds = collectTopicsFromDocument(currentDocument);

      for (const topic of topicsForDocument()) {
        if (!presentTopicIds.has(topic.id)) continue;
        const status = checkStatusForTopic(topic);
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
      <div class="verify-advanced__legend-help-popup" data-help-topic="${topic.id}" hidden>${options.escapeHtml(topic.plainEnglish || topic.description)}</div>
    `;
        li.appendChild(item);
        legend.appendChild(li);
      }
    }

    function render() {
      if (!elements?.json || !currentDocument) return;
      closeLegendHelp();
      elements.json.innerHTML = renderReceiptDocument(currentDocument);
      renderLegend();
      highlightLegendTopic(null);
      updateFocusHint(pinnedTopic);
      applyTopicFocus(pinnedTopic);
    }

    function bindEvents(els) {
      elements = els;
      if (eventsBound || !elements?.json || !elements?.legend) return;
      eventsBound = true;

      elements.json.addEventListener('mouseover', (e) => {
        const field = e.target.closest('[data-topic]');
        if (field) highlightLegendTopic(field.dataset.topic);
      });

      elements.json.addEventListener('mouseout', (e) => {
        const next = e.relatedTarget;
        if (!next || !elements.json.contains(next) || !next.closest?.('[data-topic]')) {
          highlightLegendTopic(null);
        }
      });

      elements.json.addEventListener('click', (e) => {
        const expandBtn = e.target.closest('[data-expand-path]');
        if (expandBtn) {
          e.preventDefault();
          expandedPaths.add(expandBtn.dataset.expandPath);
          render();
          return;
        }

        const collapseValueBtn = e.target.closest('[data-collapse-value-path]');
        if (collapseValueBtn) {
          e.preventDefault();
          expandedPaths.delete(collapseValueBtn.dataset.collapseValuePath);
          render();
          return;
        }

        const collapseBtn = e.target.closest('[data-collapse-path]');
        if (collapseBtn) {
          e.preventDefault();
          const path = collapseBtn.dataset.collapsePath;
          if (collapsedSections.has(path)) collapsedSections.delete(path);
          else collapsedSections.add(path);
          render();
          return;
        }

        if (!e.target.closest('[data-topic], .receipt-expand, .receipt-collapse-btn')) {
          pinnedTopic = null;
          highlightLegendTopic(null);
          updateFocusHint(null);
          applyTopicFocus(null);
        }
      });

      elements.legend.addEventListener('click', (e) => {
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

    return {
      resetState,
      bindEvents,
      render(document, context) {
        currentDocument = document;
        currentContext = context;
        render();
      },
      focusTopic,
    };
  }

  global.ReceiptExplorer = { create: createReceiptExplorer };
})(window);
