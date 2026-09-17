/* Local navigation only. The palette never submits tenant-changing actions. */
(function () {
  'use strict';
  const root = document.documentElement;
  const collapse = document.querySelector('.sidebar-toggle');
  const dialog = document.getElementById('command-palette');
  const query = document.getElementById('command-query');
  const results = document.getElementById('command-results');
  const trigger = document.querySelector('[data-open-command]');
  const close = document.querySelector('[data-close-command]');
  let opener = null;
  let active = 0;
  let matches = [];

  function setCollapsed(value) {
    root.classList.toggle('sidebar-collapsed', value);
    collapse.setAttribute('aria-expanded', String(!value));
    collapse.setAttribute('aria-label', value ? 'Expand sidebar' : 'Collapse sidebar');
    collapse.title = collapse.getAttribute('aria-label');
  }
  try { setCollapsed(localStorage.getItem('violet-sidebar-collapsed') === 'true'); } catch (_) { setCollapsed(false); }
  collapse.hidden = false;
  trigger.hidden = false;
  if (!/Mac|iPhone|iPad/.test(navigator.platform)) trigger.querySelector('kbd').textContent = 'Ctrl K';
  collapse.addEventListener('click', () => {
    const collapsed = !root.classList.contains('sidebar-collapsed');
    setCollapsed(collapsed);
    try { localStorage.setItem('violet-sidebar-collapsed', String(collapsed)); } catch (_) { /* Optional preference. */ }
  });

  const destinations = [
    { name: 'Projects', url: '/', group: 'Page' },
    { name: 'Recent runs', url: '/runs', group: 'Page' },
    { name: 'Scoring & risk settings', url: '/settings', group: 'Page' }
  ];
  document.querySelectorAll('.portfolio .project-name a').forEach(link => {
    destinations.push({ name: link.textContent.trim(), url: link.getAttribute('href'), group: 'Project' });
  });
  function select(index) {
    active = (index + matches.length) % matches.length;
    Array.from(results.children).forEach((element, i) => element.setAttribute('aria-selected', String(i === active)));
    const selected = results.children[active];
    if (selected) {
      query.setAttribute('aria-activedescendant', selected.id);
      selected.scrollIntoView({ block: 'nearest' });
    } else query.removeAttribute('aria-activedescendant');
  }
  function render() {
    const text = query.value.trim();
    matches = destinations.filter(item => item.name.toLowerCase().includes(text.toLowerCase()));
    if (text) matches.push({ name: `Search all projects for “${text}”`, url: '/?q=' + encodeURIComponent(text), group: 'Search' });
    results.replaceChildren();
    matches.forEach((item, i) => {
      const link = document.createElement('a');
      link.href = item.url;
      link.className = 'command-result';
      link.id = 'command-result-' + i;
      link.setAttribute('role', 'option');
      link.tabIndex = -1;
      const label = document.createElement('span');
      label.textContent = item.name;
      const group = document.createElement('small');
      group.textContent = item.group;
      link.append(label, group);
      link.addEventListener('pointermove', () => select(i));
      results.append(link);
    });
    select(0);
  }
  function open() {
    if (dialog.open || document.querySelector('dialog[open]')) return;
    opener = document.activeElement;
    query.value = '';
    dialog.showModal();
    render();
    query.focus();
  }
  trigger.addEventListener('click', open);
  close.addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => { if (opener) opener.focus(); });
  dialog.addEventListener('click', event => { if (event.target === dialog) { const r = dialog.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) dialog.close(); } });
  dialog.addEventListener('keydown', event => {
    if (event.key === 'Escape') { event.preventDefault(); dialog.close(); }
  });
  query.addEventListener('input', render);
  query.addEventListener('keydown', event => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); select(active + (event.key === 'ArrowDown' ? 1 : -1)); }
    if (event.key === 'Enter' && matches[active]) { event.preventDefault(); window.location.assign(matches[active].url); }
  });
  document.addEventListener('keydown', event => {
    if ((event.metaKey || event.ctrlKey) && !event.altKey && event.key.toLowerCase() === 'k') { event.preventDefault(); if (dialog.open) dialog.close(); else open(); }
  });
})();
