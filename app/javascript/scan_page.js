// Scan results page: tabs, info popovers, the Network domain list and the
// Manifest viewer. Plain script, loaded at the end of the page. Everything
// shown from scan data is inserted with textContent: names, manifest values
// and URLs come from untrusted extension code.
(function () {
  'use strict';

  function formatNumber(n) {
    return n.toLocaleString('en-US');
  }

  function plural(n, one, many) {
    return formatNumber(n) + ' ' + (n === 1 ? one : many);
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // Clipboard API where allowed, otherwise the older selection-based copy.
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      const area = el('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.append(area);
      area.select();
      const ok = document.execCommand('copy');
      area.remove();
      ok ? resolve() : reject(new Error('copy failed'));
    });
  }

  // ---- Tabs ---------------------------------------------------------------

  const tabsApi = (function initTabs() {
    const tablist = document.getElementById('scan-tabs');
    if (!tablist) return null;

    const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));
    const activeClasses = tablist.dataset.activeClass.split(' ');
    const inactiveClasses = tablist.dataset.inactiveClass.split(' ');
    const ids = tabs.map(function (tab) { return tab.dataset.tabsTarget; });
    let aliases = {};
    try { aliases = JSON.parse(tablist.dataset.aliases || '{}'); } catch (e) { aliases = {}; }

    function tabFromHash() {
      const id = window.location.hash.slice(1);
      if (ids.includes(id)) return id;
      if (Object.prototype.hasOwnProperty.call(aliases, id)) return aliases[id];
      return ids[0];
    }

    function selectTab(targetId, options) {
      options = options || {};
      tabs.forEach(function (tab) {
        const selected = tab.dataset.tabsTarget === targetId;
        tab.setAttribute('aria-selected', selected ? 'true' : 'false');
        tab.setAttribute('tabindex', selected ? '0' : '-1');
        tab.classList.remove.apply(tab.classList, selected ? inactiveClasses : activeClasses);
        tab.classList.add.apply(tab.classList, selected ? activeClasses : inactiveClasses);

        const panel = document.getElementById(tab.dataset.tabsTarget);
        if (panel) {
          panel.classList.toggle('hidden', !selected);
          panel.classList.toggle('block', selected);
        }
        if (selected && options.focus) tab.focus();
      });

      // Record the tab in the URL without scrolling, so links and Back work.
      if (options.updateHash && window.location.hash.slice(1) !== targetId) {
        history.pushState(null, '', '#' + targetId);
      }
    }

    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () {
        selectTab(this.dataset.tabsTarget, { updateHash: true });
      });
    });

    tablist.addEventListener('keydown', function (e) {
      const current = tabs.indexOf(document.activeElement);
      if (current === -1) return;

      let next = null;
      if (e.key === 'ArrowRight') next = (current + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') next = (current - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabs.length - 1;
      if (next === null) return;

      e.preventDefault();
      selectTab(tabs[next].dataset.tabsTarget, { focus: true, updateHash: true });
      tabs[next].scrollIntoView({ block: 'nearest', inline: 'nearest' });
    });

    // Old links (#analysis, #details) open their new tab under the new address.
    function selectFromHash() {
      const target = tabFromHash();
      const hash = window.location.hash.slice(1);
      if (hash !== target && Object.prototype.hasOwnProperty.call(aliases, hash)) {
        history.replaceState(null, '', '#' + target);
      }
      selectTab(target);
    }

    window.addEventListener('popstate', selectFromHash);
    window.addEventListener('hashchange', selectFromHash);
    selectFromHash();

    return { select: selectTab };
  })();

  // ---- Info popovers: toggle on click, close on Escape or a click outside --

  (function initPopovers() {
    const buttons = Array.from(document.querySelectorAll('[data-popover-target]'));
    if (buttons.length === 0) return;

    function setOpen(button, open) {
      const popup = document.getElementById(button.dataset.popoverTarget);
      if (!popup) return;
      popup.classList.toggle('hidden', !open);
      button.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    function closeAll(except) {
      buttons.forEach(function (button) { if (button !== except) setOpen(button, false); });
    }

    buttons.forEach(function (button) {
      button.addEventListener('click', function () {
        const open = this.getAttribute('aria-expanded') !== 'true';
        closeAll(this);
        setOpen(this, open);
      });
    });

    document.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape') return;
      const openButton = buttons.find(function (b) { return b.getAttribute('aria-expanded') === 'true'; });
      if (!openButton) return;
      closeAll();
      openButton.focus();
    });

    document.addEventListener('click', function (e) {
      buttons.forEach(function (button) {
        const popup = document.getElementById(button.dataset.popoverTarget);
        if (button.contains(e.target) || (popup && popup.contains(e.target))) return;
        setOpen(button, false);
      });
    });
  })();

  // ---- Network: one row per domain, built on demand ------------------------

  (function initNetwork() {
    const list = document.getElementById('network-domains');
    if (!list) return;

    // See ScanPage::NetworkDomains#encoded for the format.
    let labels;
    try { labels = JSON.parse(list.dataset.labels); } catch (e) { return; }

    const search = document.getElementById('network-search');
    const category = document.getElementById('network-category');
    const status = document.getElementById('network-status');
    const more = document.getElementById('network-more');
    const pageSize = Number(list.dataset.pageSize) || 50;
    const urlPageSize = Number(list.dataset.urlPageSize) || 200;

    const domains = (list.dataset.domains || '').split('\n').filter(Boolean).map(function (line, index) {
      const fields = line.split('\t');
      const bits = Number(fields[2]) || 0;
      return {
        id: index,
        name: fields[0],
        category: Number(fields[1]) || 0,
        flags: labels.flags.filter(function (label, i) { return bits & (1 << i); }),
        urls: fields.slice(3),
        haystack: null
      };
    });
    const expanded = new Set();
    let query = '';
    let shown = pageSize;
    let matches = domains;

    const chipClass = 'inline-block px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200';
    const flagClass = 'inline-block px-1.5 py-0.5 rounded text-xs border border-gray-400 text-gray-700 dark:border-gray-500 dark:text-gray-300';
    const smallButton = 'px-2 py-0.5 text-xs font-medium rounded border border-brand-600 text-brand-700 hover:bg-brand-50 dark:border-brand-300 dark:text-brand-200 dark:hover:bg-gray-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500';

    function haystack(domain) {
      if (domain.haystack === null) domain.haystack = (domain.name + '\n' + domain.urls.join('\n')).toLowerCase();
      return domain.haystack;
    }

    function visibleUrls(domain) {
      if (!query || domain.name.toLowerCase().includes(query)) return domain.urls;
      return domain.urls.filter(function (url) { return url.toLowerCase().includes(query); });
    }

    function renderUrls(domain, panel) {
      const urls = visibleUrls(domain);
      const limit = Number(panel.dataset.limit) || urlPageSize;
      const ul = panel.querySelector('ul');
      ul.replaceChildren.apply(ul, urls.slice(0, limit).map(function (url) {
        return el('li', 'py-0.5 font-mono text-xs leading-5 whitespace-pre-wrap break-all text-gray-700 dark:text-gray-300', url);
      }));
      const note = panel.querySelector('[data-url-note]');
      note.textContent = urls.length === domain.urls.length
        ? (urls.length > limit ? 'Showing ' + formatNumber(limit) + ' of ' + plural(urls.length, 'URL', 'URLs') : '')
        : 'Showing ' + formatNumber(Math.min(limit, urls.length)) + ' of ' + formatNumber(urls.length) + ' matching (' + plural(domain.urls.length, 'URL', 'URLs') + ' in all)';
      const moreUrls = panel.querySelector('[data-more-urls]');
      moreUrls.hidden = urls.length <= limit;
    }

    function buildRow(domain) {
      const li = el('li', 'py-1');
      const panelId = 'network-domain-' + domain.id;

      const toggle = el('button', 'w-full flex items-start gap-2 text-left px-2 py-2 rounded hover:bg-gray-50 dark:hover:bg-gray-700/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500');
      toggle.type = 'button';
      toggle.setAttribute('aria-controls', panelId);
      toggle.setAttribute('aria-expanded', expanded.has(domain.id) ? 'true' : 'false');

      const arrow = el('span', 'shrink-0 text-gray-500 dark:text-gray-400', expanded.has(domain.id) ? '▾' : '▸');
      arrow.setAttribute('aria-hidden', 'true');
      const body = el('span', 'flex-1 min-w-0 flex flex-wrap items-center gap-x-2 gap-y-1');
      body.append(el('span', 'font-mono text-sm text-gray-800 dark:text-gray-100 break-all', domain.name));
      const categoryLabel = labels.categories[domain.category] || 'Other';
      // Most rows are Other, so its chip is left out; the filter still offers it.
      if (categoryLabel !== 'Other') body.append(el('span', chipClass, categoryLabel));
      // A flag that only repeats the category (link shortener, IP address) is left out.
      domain.flags.forEach(function (flag) {
        if (flag.toLowerCase() !== categoryLabel.toLowerCase()) body.append(el('span', flagClass, flag));
      });
      const count = el('span', 'shrink-0 text-sm tabular-nums text-gray-600 dark:text-gray-300', plural(domain.urls.length, 'URL', 'URLs'));
      toggle.append(arrow, body, count);

      const panel = el('div', 'ml-6 mr-2 mb-2 p-2 rounded bg-gray-50 dark:bg-gray-900/60');
      panel.id = panelId;
      panel.hidden = !expanded.has(domain.id);

      const tools = el('div', 'flex flex-wrap items-center gap-2 mb-1');
      const copy = el('button', smallButton, 'Copy ' + plural(domain.urls.length, 'URL', 'URLs'));
      copy.type = 'button';
      const copyStatus = el('span', 'text-xs text-gray-600 dark:text-gray-300');
      copyStatus.setAttribute('role', 'status');
      copy.addEventListener('click', function () {
        copyText(domain.urls.join('\n')).then(
          function () { copyStatus.textContent = 'Copied.'; },
          function () { copyStatus.textContent = 'Could not copy.'; }
        );
      });
      const note = el('span', 'text-xs text-gray-500 dark:text-gray-400');
      note.setAttribute('data-url-note', '');
      tools.append(copy, note, copyStatus);

      const ul = el('ul');
      ul.setAttribute('aria-label', 'URLs on ' + domain.name);
      const moreUrls = el('button', smallButton + ' mt-2', 'Show more URLs');
      moreUrls.type = 'button';
      moreUrls.setAttribute('data-more-urls', '');
      moreUrls.addEventListener('click', function () {
        panel.dataset.limit = String((Number(panel.dataset.limit) || urlPageSize) + urlPageSize);
        renderUrls(domain, panel);
      });
      panel.append(tools, ul, moreUrls);

      toggle.addEventListener('click', function () {
        const open = !expanded.has(domain.id);
        if (open) expanded.add(domain.id); else expanded.delete(domain.id);
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        arrow.textContent = open ? '▾' : '▸';
        panel.hidden = !open;
        // URLs are only put in the DOM while their row is open.
        if (open) renderUrls(domain, panel); else ul.replaceChildren();
      });

      if (expanded.has(domain.id)) renderUrls(domain, panel);
      li.append(toggle, panel);
      return li;
    }

    function render() {
      const rows = matches.slice(0, shown).map(buildRow);
      list.replaceChildren.apply(list, rows);
      more.classList.toggle('hidden', matches.length <= shown);
      const filtered = query || category.value;
      if (matches.length === 0) {
        status.textContent = 'No domains match.';
      } else if (filtered) {
        status.textContent = plural(matches.length, 'domain matches', 'domains match') +
          (matches.length > shown ? '; showing the first ' + formatNumber(shown) + '.' : '.');
      } else {
        status.textContent = matches.length > shown
          ? 'Showing ' + formatNumber(shown) + ' of ' + plural(matches.length, 'domain', 'domains') + ', most URLs first.'
          : plural(matches.length, 'domain', 'domains') + ', most URLs first.';
      }
    }

    function applyFilters() {
      query = search.value.trim().toLowerCase();
      const wanted = category.value === '' ? null : Number(category.value);
      matches = domains.filter(function (d) {
        return (wanted === null || d.category === wanted) && (!query || haystack(d).includes(query));
      });
      shown = pageSize;
      render();
    }

    let timer = null;
    search.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(applyFilters, 150);
    });
    category.addEventListener('change', applyFilters);
    more.addEventListener('click', function () {
      shown += pageSize;
      render();
    });

    render();
  })();

  // ---- Manifest viewer --------------------------------------------------------
  // Markup: app/views/scan/_manifest.html.erb; looks: application.css. Lines
  // are .ml rows numbered by data-line from 1, in order. A line with notes is
  // followed by a .mn row (data-for = its line). Rows inside a long array
  // carry data-groups, and the array's button carries data-group-toggle.
  // Everything here only flips attributes and classes; nothing is measured.

  const manifestApi = (function initManifest() {
    const code = document.getElementById('manifest-code');
    if (!code) return null;

    const status = document.getElementById('manifest-status');
    const lines = Array.from(code.querySelectorAll('.ml'));
    const grouped = Array.from(code.querySelectorAll('[data-groups]'));
    const toggles = Array.from(code.querySelectorAll('[data-group-toggle]'));
    const collapsed = new Set(toggles
      .filter(function (b) { return b.getAttribute('aria-expanded') === 'false'; })
      .map(function (b) { return b.dataset.groupToggle; }));
    const noted = Array.from(code.querySelectorAll('.mn')).map(function (n) { return Number(n.dataset.for); });
    const prev = document.getElementById('manifest-prev');
    const next = document.getElementById('manifest-next');
    const position = document.getElementById('manifest-position');
    const notesToggle = document.getElementById('manifest-notes-toggle');
    let current = -1;
    let marked = [];

    function lineAt(n) {
      const line = lines[n - 1];
      return line && Number(line.dataset.line) === n ? line : null;
    }

    // The file as stored: line text only, without numbers or notes.
    function manifestText() {
      return lines.map(function (line) { return line.textContent; }).join('\n') + '\n';
    }

    function refreshFolds() {
      grouped.forEach(function (node) {
        const hide = node.dataset.groups.split(' ').some(function (id) { return collapsed.has(id); });
        if (node.hidden !== hide) node.hidden = hide;
      });
      toggles.forEach(function (button) {
        const open = !collapsed.has(button.dataset.groupToggle);
        button.setAttribute('aria-expanded', open ? 'true' : 'false');
        button.textContent = open ? button.dataset.openLabel : button.dataset.closedLabel;
      });
    }

    function unfoldAround(line) {
      (line.dataset.groups || '').split(' ').forEach(function (id) { if (id) collapsed.delete(id); });
    }

    code.addEventListener('click', function (e) {
      const button = e.target.closest('[data-group-toggle]');
      if (!button) return;
      const id = button.dataset.groupToggle;
      if (collapsed.has(id)) collapsed.delete(id); else collapsed.add(id);
      refreshFolds();
    });

    const copy = document.getElementById('manifest-copy');
    copy.addEventListener('click', function () {
      copyText(manifestText()).then(
        function () { status.textContent = 'Manifest copied.'; copy.textContent = 'Copied'; },
        function () { status.textContent = 'Could not copy the manifest.'; }
      );
      setTimeout(function () { copy.textContent = 'Copy'; }, 2000);
    });

    document.getElementById('manifest-download').addEventListener('click', function () {
      const url = URL.createObjectURL(new Blob([manifestText()], { type: 'application/json' }));
      const link = el('a');
      link.href = url;
      link.download = 'manifest.json';
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    });

    const wrap = document.getElementById('manifest-wrap');
    wrap.addEventListener('click', function () {
      const on = code.dataset.wrap !== 'true';
      code.dataset.wrap = on ? 'true' : 'false';
      wrap.setAttribute('aria-pressed', on ? 'true' : 'false');
    });

    function setNotes(on) {
      code.dataset.notes = on ? 'on' : 'off';
      if (notesToggle) notesToggle.setAttribute('aria-pressed', on ? 'true' : 'false');
      if (prev) prev.disabled = !on;
      if (next) next.disabled = !on;
      if (!on) {
        mark([]);
        current = -1;
        if (position) position.textContent = '';
      }
      status.textContent = on ? 'Notes shown.' : 'Notes hidden.';
    }

    function mark(nodes) {
      marked.forEach(function (node) { node.classList.remove('is-target'); });
      marked = nodes;
      marked.forEach(function (node) { node.classList.add('is-target'); });
    }

    // Shows "3 of 17" and, for screen readers, says where the line is and
    // what its notes are (all read from the page, set as text).
    function updatePosition(line) {
      const lineNumber = Number(line.dataset.line);
      current = noted.indexOf(lineNumber);
      if (position) position.textContent = current < 0 ? '' : (current + 1) + ' of ' + noted.length;
      const parts = [current < 0 ? 'Line ' + lineNumber + '.' : 'Note ' + (current + 1) + ' of ' + noted.length + ', line ' + lineNumber + ':'];
      parts.push(line.textContent.trim());
      const note = document.getElementById('manifest-note-' + lineNumber);
      if (note) {
        note.querySelectorAll('.mn-item').forEach(function (item) {
          const sev = item.querySelector('.mn-sev');
          const title = item.querySelector('.mn-title');
          parts.push((sev ? sev.textContent + ': ' : '') + (title ? title.textContent : '') + '.');
        });
      }
      status.textContent = parts.join(' ');
    }

    // The notes bar sticks under the page's tab bar, and a line scrolled to
    // must clear both. Their heights are read once here and once per jump,
    // after all the changes above, so each jump costs a single layout.
    const viewer = code.closest('.manifest-viewer');
    const tabBar = document.getElementById('scan-tabs');
    const stickyTabs = tabBar && tabBar.closest('.sticky');
    const summary = document.getElementById('manifest-summary');

    function measureStickyBars() {
      if (!viewer) return;
      const top = stickyTabs ? stickyTabs.offsetHeight : null;
      const bar = summary && summary.hasAttribute('data-sticky') ? summary.offsetHeight : 0;
      if (top !== null) viewer.style.setProperty('--mv-sticky-top', top + 'px');
      viewer.style.setProperty('--mv-summary-h', bar + 'px');
    }
    measureStickyBars();

    // Unfolds, marks and scrolls to the line. With focus, it also moves
    // focus there (its note describes it); Previous and Next keep focus on
    // themselves so they can be pressed again, and announce the note instead.
    function open(line, extra, focus) {
      if (code.dataset.notes === 'off') setNotes(true);
      unfoldAround(line);
      refreshFolds();
      mark([line].concat(extra || []));
      updatePosition(line);
      measureStickyBars();
      line.scrollIntoView({ block: 'start', inline: 'start' });
      if (focus) {
        line.setAttribute('tabindex', '-1');
        line.focus({ preventScroll: true });
      }
    }

    // Opens the slim (Low, Minimal, Info) notes inside the given nodes, so
    // the explanation shows wherever the reader was taken.
    function expand(nodes) {
      nodes.forEach(function (node) {
        node.querySelectorAll('details').forEach(function (details) { details.open = true; });
      });
    }

    function step(by) {
      if (noted.length === 0) return;
      const index = current < 0 ? (by > 0 ? 0 : noted.length - 1) : (current + by + noted.length) % noted.length;
      const line = lineAt(noted[index]);
      if (!line) return;
      const note = document.getElementById('manifest-note-' + line.dataset.line);
      if (note) expand([note]);
      open(line, [], false);
    }

    if (prev) prev.addEventListener('click', function () { step(-1); });
    if (next) next.addEventListener('click', function () { step(1); });
    if (notesToggle) {
      notesToggle.addEventListener('click', function () { setNotes(code.dataset.notes === 'off'); });
    }

    // Opens the lines of one finding; ref (data-manifest-finding) picks out
    // that finding's entry in the notes.
    function show(numbers, ref) {
      const targets = numbers.map(lineAt).filter(Boolean);
      if (targets.length === 0) return;
      targets.forEach(unfoldAround);
      const items = /^\d+$/.test(ref || '')
        ? Array.from(code.querySelectorAll('.mn-item[data-note-for="' + ref + '"]'))
        : [];
      expand(items);
      open(targets[0], targets.slice(1).concat(items), true);
    }

    return { show: show };
  })();

  document.querySelectorAll('[data-manifest-lines]').forEach(function (button) {
    button.addEventListener('click', function () {
      if (!tabsApi || !manifestApi) return;
      tabsApi.select('manifest', { updateHash: true });
      manifestApi.show(this.dataset.manifestLines.split(' ').map(Number), this.dataset.manifestFinding);
    });
  });

  // ---- Store version ------------------------------------------------------
  // After the page has loaded, asks the server which version the Chrome Web
  // Store offers now (the server caches Google's answer), then shows it next
  // to the scanned version and, when they differ, fills in the notice above
  // the header. The server writes all sentences; they are set as text only.
  // Failures leave the page as it was rendered.
  (function initStoreVersion() {
    const freshness = document.getElementById('scan-freshness');
    const url = freshness && freshness.dataset.storeVersionUrl;
    if (!url || !window.fetch) return;

    const banner = freshness.querySelector('[data-freshness-banner]');
    const message = freshness.querySelector('[data-freshness-message]');
    const note = document.querySelector('[data-store-version-note]');
    const rescanLink = document.querySelector('[data-rescan-link]');

    function text(value) {
      return typeof value === 'string' ? value : '';
    }

    function swapClasses(node, from, to) {
      if (!node || from === undefined || to === undefined) return;
      node.classList.remove.apply(node.classList, from.split(' ').filter(Boolean));
      node.classList.add.apply(node.classList, to.split(' ').filter(Boolean));
    }

    fetch(url, { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (data) {
        if (!data || typeof data !== 'object') return;

        if (note) {
          const noteText = text(data.store_note);
          note.textContent = noteText ? ' · ' + noteText : '';
          if (data.version_differs === true) {
            swapClasses(note, note.dataset.quietClass, note.dataset.differsClass);
          } else {
            swapClasses(note, note.dataset.differsClass, note.dataset.quietClass);
          }
        }

        if (rescanLink && data.rescan_allowed === true) rescanLink.hidden = false;

        // Only touch the live region when the words change, so an unchanged
        // notice is not read out again.
        const notice = text(data.notice);
        if (banner && message && notice) {
          if (message.textContent.trim() !== notice) message.textContent = notice;
          banner.hidden = false;
        }
      })
      .catch(function () { /* keep the page as rendered */ });
  })();
})();
