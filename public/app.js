'use strict';
/*
 * TrustVault front end. Plain JavaScript, no framework, no build step.
 *
 * Security notes for reviewers:
 *  - All dynamic content is inserted with textContent / text nodes (see h()). There is no innerHTML anywhere,
 *    so a malicious file name or tag cannot become markup.
 *  - Hiding a button is NOT access control. Every action below is re-checked by the server on each request.
 *  - The CSRF token is held in memory only (never in storage) and sent as a header on every state-changing call.
 */
(() => {
  const root = document.getElementById('app');
  const state = { user: null, csrf: null, folders: [], docFilter: { q: '', scope: 'all', tag: '', folder: '', sort: 'updated' } };

  // ---------- tiny DOM helper ----------
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'value') el.value = v;
      else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'multiple') el[k] = !!v;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
  const mount = (node) => { clear(root); root.append(node); window.scrollTo(0, 0); };

  // ---------- formatting ----------
  const fmtSize = (n) => (n == null ? '' : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
  const fmtDate = (ms) => (ms ? new Date(ms).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '-');
  const fmtDay = (ms) => (ms ? new Date(ms).toLocaleDateString([], { dateStyle: 'medium' }) : '-');
  function ago(ms) {
    const s = Math.round((Date.now() - ms) / 1000);
    if (s < 60) return 'just now'; if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`; return `${Math.floor(s / 86400)} d ago`;
  }
  const ext = (name) => (name && name.includes('.') ? name.split('.').pop().slice(0, 4) : 'file');
  const dateInputToMs = (v) => { if (!v) return null; const [y, m, d] = v.split('-').map(Number); return new Date(y, m - 1, d, 23, 59, 0).getTime(); };
  const inDays = (n) => { const d = new Date(Date.now() + n * 86400000); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };

  // ---------- toasts & modal ----------
  function toast(msg, kind = 'ok') {
    const t = h('div', { class: `toast ${kind === 'error' ? 'error' : ''}`, role: kind === 'error' ? 'alert' : 'status' }, msg);
    document.getElementById('toasts').append(t);
    setTimeout(() => t.remove(), kind === 'error' ? 6000 : 3500);
  }
  function modal(title, body, actions) {
    const back = h('div', { class: 'modal-back', role: 'dialog', 'aria-modal': 'true', 'aria-label': title });
    const close = () => back.remove();
    const box = h('div', { class: 'modal' }, h('h2', {}, title), body, h('div', { class: 'row', style: undefined }, actions(close)));
    back.append(box);
    back.addEventListener('click', (e) => { if (e.target === back) close(); });
    document.body.append(back);
    const first = box.querySelector('input,select,textarea,button');
    if (first) first.focus();
    return close;
  }

  // ---------- API ----------
  async function api(method, path, { json, body, headers = {} } = {}) {
    const opts = { method, headers: { ...headers }, credentials: 'same-origin' };
    if (method !== 'GET' && state.csrf) opts.headers['x-csrf-token'] = state.csrf;
    if (json !== undefined) { opts.body = JSON.stringify(json); opts.headers['content-type'] = 'application/json'; }
    if (body !== undefined) opts.body = body;
    let res;
    try { res = await fetch(path, opts); } catch { throw new Error('Network error - is the server reachable?'); }
    if (res.status === 204) return {};
    const isJson = (res.headers.get('content-type') || '').includes('application/json');
    const data = isJson ? await res.json() : null;
    if (!res.ok) {
      if (res.status === 401 && state.user) { state.user = null; state.csrf = null; location.hash = '#/login'; toast('Your session ended. Please sign in again.', 'error'); }
      if (res.status === 403 && data && data.code === 'PASSWORD_CHANGE_REQUIRED') { location.hash = '#/password'; }
      const err = new Error((data && data.error) || `Request failed (${res.status})`);
      err.status = res.status; err.data = data;
      throw err;
    }
    return data || {};
  }
  const guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, 'error'); } };

  async function download(url, fallbackName) {
    const res = await fetch(url, { credentials: 'same-origin' });
    if (!res.ok) { let m = `Download failed (${res.status})`; try { m = (await res.json()).error || m; } catch { /* keep */ } throw new Error(m); }
    const cd = res.headers.get('content-disposition') || '';
    const star = /filename\*=UTF-8''([^;]+)/i.exec(cd);
    const name = star ? decodeURIComponent(star[1]) : fallbackName;
    const blob = await res.blob();
    const href = URL.createObjectURL(blob);
    const a = h('a', { href, download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(href), 10000);
  }

  // ---------- layout ----------
  const isOwner = () => state.user && state.user.role === 'owner';
  const isAdmin = () => state.user && state.user.role === 'admin';

  function shell(active, content) {
    const link = (hash, label, key) => h('a', { href: hash, class: active === key ? 'active' : '', 'aria-current': active === key ? 'page' : undefined }, label);
    return h('div', {},
      h('header', { class: 'topbar' }, h('div', { class: 'topbar-inner' },
        h('a', { class: 'brand', href: '#/' }, h('img', { src: '/favicon.svg', alt: '' }), 'TrustVault'),
        h('nav', { class: 'nav', 'aria-label': 'Main' },
          !isAdmin() && link('#/', 'Documents', 'docs'),
          isOwner() && link('#/trash', 'Trash', 'trash'),
          isAdmin() && link('#/admin', 'Admin', 'admin'),
          link('#/account', 'Account', 'account')),
        h('div', { class: 'userbox' },
          h('span', { class: 'who' }, state.user.name), h('span', { class: `badge ${state.user.role}` }, state.user.role),
          state.user.isExternal && h('span', { class: 'badge external' }, 'external'),
          h('button', { class: 'small', onclick: guard(logout) }, 'Sign out')))),
      h('main', { id: 'main' }, content));
  }

  async function logout() {
    try { await api('POST', '/api/auth/logout', { json: {} }); } catch { /* ignore */ }
    state.user = null; state.csrf = null; location.hash = '#/login';
  }

  // ---------- login ----------
  function viewLogin() {
    const err = h('p', { class: 'badge bad', role: 'alert', hidden: true });
    const email = h('input', { id: 'email', type: 'email', autocomplete: 'username', required: true });
    const pw = h('input', { id: 'pw', type: 'password', autocomplete: 'current-password', required: true });
    const btn = h('button', { class: 'primary', type: 'submit' }, 'Sign in');
    const form = h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault(); err.hidden = true; btn.disabled = true;
      try {
        const r = await api('POST', '/api/auth/login', { json: { email: email.value, password: pw.value } });
        state.user = r.user; state.csrf = r.csrfToken;
        location.hash = r.user.mustChangePassword ? '#/password' : (r.user.role === 'admin' ? '#/admin' : '#/');
        route();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; pw.value = ''; } finally { btn.disabled = false; }
    } },
    h('div', {}, h('label', { for: 'email' }, 'Email'), email),
    h('div', {}, h('label', { for: 'pw' }, 'Password'), pw), err, btn);

    const demo = (e, p) => h('div', {}, h('button', { class: 'link', type: 'button', onclick: () => { email.value = e; pw.value = p; } }, e));
    mount(h('div', { class: 'login-wrap' }, h('div', { class: 'login-card' }, h('div', { class: 'card stack' },
      h('div', { class: 'row' }, h('img', { src: '/favicon.svg', alt: '', width: 36, height: 36 }), h('h1', {}, 'TrustVault')),
      h('p', { class: 'muted' }, 'Secure document sharing. Only the right people can open a file, and every access is on record.'),
      form,
      h('div', { class: 'demo-box' }, h('b', {}, 'Demo accounts'), h('span', { class: 'muted' }, ' (tap to fill; passwords are in the README)'),
        demo('admin@trustvault.demo', 'Admin#Demo2026'), demo('alice@trustvault.demo', 'Owner#Demo2026'), demo('bob@trustvault.demo', 'Owner#Demo2026'),
        demo('carol@trustvault.demo', 'Viewer#Demo2026'), demo('partner@external.demo', 'Partner#Demo2026'))))));
  }

  // ---------- change password ----------
  function viewPassword() {
    const forced = state.user.mustChangePassword;
    const cur = h('input', { id: 'cur', type: 'password', autocomplete: 'current-password', required: true });
    const nw = h('input', { id: 'nw', type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
    const content = h('div', { class: 'card stack', style: undefined },
      h('h1', {}, forced ? 'Choose a new password' : 'Change password'),
      forced && h('p', { class: 'badge medium' }, 'You are using a temporary password. Set your own to continue.'),
      h('form', { class: 'stack', onsubmit: guard(async (e) => {
        e.preventDefault();
        await api('POST', '/api/auth/password', { json: { currentPassword: cur.value, newPassword: nw.value } });
        state.user.mustChangePassword = false; toast('Password changed. Other devices were signed out.');
        location.hash = isAdmin() ? '#/admin' : '#/'; route();
      }) },
      h('div', {}, h('label', { for: 'cur' }, 'Current password'), cur),
      h('div', {}, h('label', { for: 'nw' }, 'New password'), nw, h('p', { class: 'hint' }, 'At least 10 characters. Changing it signs out all your other sessions.')),
      h('button', { class: 'primary', type: 'submit' }, 'Save password')));
    if (forced) { mount(h('div', {}, h('main', {}, content))); return; }
    mount(shell('account', content));
  }

  function viewAccount() {
    const u = state.user;
    const roleText = { admin: 'Administrator: manages accounts, sees document metadata and the audit trail. Cannot open file contents.', owner: 'Document owner: uploads documents and decides who can read or edit them.', viewer: 'Viewer: read-only access to documents shared with you.' }[u.role];
    mount(shell('account', h('div', { class: 'stack' },
      h('div', { class: 'card stack' }, h('h1', {}, 'Your account'),
        h('div', {}, h('b', {}, u.name), h('div', { class: 'muted' }, u.email)),
        h('div', { class: 'row' }, h('span', { class: `badge ${u.role}` }, u.role), u.isExternal && h('span', { class: 'badge external' }, 'external'), u.department && h('span', { class: 'badge' }, u.department)),
        h('p', { class: 'muted' }, roleText),
        h('div', {}, h('a', { class: 'btn', href: '#/password' }, 'Change password'))))));
  }

  // ---------- documents list ----------
  async function loadFolders() {
    if (!isOwner()) { state.folders = []; return; }
    try { state.folders = (await api('GET', '/api/folders')).folders; } catch { state.folders = []; }
  }

  async function viewDocuments() {
    await loadFolders();
    const f = state.docFilter;
    const listBox = h('div', { 'aria-live': 'polite' });
    const tagBox = h('div', { class: 'tags' });
    const search = h('input', { type: 'search', placeholder: 'Search name, description or tag', value: f.q, 'aria-label': 'Search documents' });
    const scope = h('select', { 'aria-label': 'Show' },
      ...[['all', 'Everything I can open'], ['mine', 'Owned by me'], ['shared', 'Shared with me']].filter(([v]) => isOwner() || v !== 'mine').map(([v, l]) => h('option', { value: v, selected: f.scope === v }, l)));
    const sort = h('select', { 'aria-label': 'Sort by' }, ...[['updated', 'Recently updated'], ['name', 'Name'], ['created', 'Newest']].map(([v, l]) => h('option', { value: v, selected: f.sort === v }, l)));
    const folderSel = isOwner() ? h('select', { 'aria-label': 'Folder' }, h('option', { value: '' }, 'All folders'), h('option', { value: 'none', selected: f.folder === 'none' }, 'No folder'),
      ...state.folders.map((x) => h('option', { value: x.id, selected: f.folder === x.id }, `${x.name} (${x.count})`))) : null;

    async function refresh() {
      const qs = new URLSearchParams();
      if (f.q) qs.set('q', f.q); if (f.scope !== 'all') qs.set('scope', f.scope); if (f.tag) qs.set('tag', f.tag); if (f.folder) qs.set('folder', f.folder); qs.set('sort', f.sort);
      if (f.sort === 'name') qs.set('dir', 'asc');
      try {
        const [d, t] = await Promise.all([api('GET', `/api/documents?${qs}`), api('GET', '/api/tags')]);
        clear(tagBox);
        if (f.tag) tagBox.append(h('button', { class: 'chip active', onclick: () => { f.tag = ''; refresh(); } }, `${f.tag} x`));
        for (const x of t.tags.filter((x) => x.tag !== f.tag).slice(0, 12)) tagBox.append(h('button', { class: 'chip', onclick: () => { f.tag = x.tag; refresh(); } }, `${x.tag} (${x.count})`));
        clear(listBox);
        if (!d.documents.length) listBox.append(h('div', { class: 'empty' }, f.q || f.tag ? 'No documents match.' : (isOwner() ? 'No documents yet. Upload your first one above.' : 'Nothing has been shared with you yet.')));
        for (const doc of d.documents) listBox.append(docItem(doc));
      } catch (e) { toast(e.message, 'error'); }
    }
    let timer;
    search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { f.q = search.value.trim(); refresh(); }, 250); });
    scope.addEventListener('change', () => { f.scope = scope.value; refresh(); });
    sort.addEventListener('change', () => { f.sort = sort.value; refresh(); });
    if (folderSel) folderSel.addEventListener('change', () => { f.folder = folderSel.value; refresh(); });

    mount(shell('docs', h('div', {},
      isOwner() && uploadCard(refresh),
      h('div', { class: 'card stack' }, h('div', { class: 'row between' }, h('h1', {}, 'Documents'), isOwner() && h('button', { class: 'small', onclick: guard(manageFolders) }, 'Folders')),
        h('div', { class: 'grid cols-2' }, search, scope, folderSel, sort), tagBox, listBox))));
    refresh();
  }

  function docItem(doc) {
    return h('a', { class: 'doc', href: `#/doc/${doc.id}` }, h('div', { class: 'doc-item' },
      h('div', { class: 'doc-icon' }, ext(doc.fileName)),
      h('div', { class: 'doc-main' },
        h('div', { class: 'doc-title' }, doc.name),
        h('div', { class: 'muted small' }, `${doc.fileName || ''} · ${fmtSize(doc.size)} · v${doc.currentVersion} · updated ${ago(doc.updatedAt)}`),
        h('div', { class: 'muted small' }, doc.myPermission === 'owner' ? 'You own this' : `Owner: ${doc.owner ? doc.owner.name : 'unknown'}`),
        doc.tags.length > 0 && h('div', { class: 'tags' }, doc.tags.map((t) => h('span', { class: 'badge' }, t)))),
      h('span', { class: `badge ${doc.myPermission}` }, doc.myPermission)));
  }

  function uploadCard(onDone) {
    const fileIn = h('input', { type: 'file', id: 'file', 'aria-label': 'Choose a file' });
    const title = h('input', { placeholder: 'Title (optional, defaults to file name)', 'aria-label': 'Title' });
    const desc = h('input', { placeholder: 'Description (optional)', 'aria-label': 'Description' });
    const tags = h('input', { placeholder: 'Tags, comma separated (e.g. hr, contract)', 'aria-label': 'Tags' });
    const folder = h('select', { 'aria-label': 'Folder' }, h('option', { value: '' }, 'No folder'), ...state.folders.map((x) => h('option', { value: x.id }, x.name)));
    const btn = h('button', { class: 'primary', type: 'button' }, 'Upload');
    const zone = h('div', { class: 'dropzone' }, 'Drop a file here or choose one. Allowed: pdf, docx, xlsx, pptx, png, jpg, txt, csv, md (max 10 MB).');
    ['dragenter', 'dragover'].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add('over'); }));
    ['dragleave', 'drop'].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove('over'); }));
    zone.addEventListener('drop', (e) => { if (e.dataTransfer.files[0]) { const dt = new DataTransfer(); dt.items.add(e.dataTransfer.files[0]); fileIn.files = dt.files; } });
    btn.addEventListener('click', guard(async () => {
      const file = fileIn.files[0];
      if (!file) throw new Error('Choose a file first');
      btn.disabled = true; btn.textContent = 'Uploading...';
      try {
        const qs = new URLSearchParams({ name: file.name });
        if (title.value.trim()) qs.set('title', title.value.trim());
        if (desc.value.trim()) qs.set('description', desc.value.trim());
        if (tags.value.trim()) qs.set('tags', tags.value.trim());
        if (folder.value) qs.set('folderId', folder.value);
        const r = await api('POST', `/api/documents?${qs}`, { body: file, headers: { 'content-type': 'application/octet-stream' } });
        toast('Uploaded. It is private to you until you share it.');
        fileIn.value = ''; title.value = ''; desc.value = ''; tags.value = '';
        location.hash = `#/doc/${r.document.id}`;
      } finally { btn.disabled = false; btn.textContent = 'Upload'; }
    }));
    return h('div', { class: 'card stack' }, h('h2', {}, 'Upload a document'), zone, fileIn,
      h('div', { class: 'grid cols-2' }, title, desc, tags, folder), h('div', {}, btn));
  }

  function manageFolders() {
    const list = h('div', { class: 'stack' });
    const name = h('input', { placeholder: 'New folder name', 'aria-label': 'New folder name' });
    async function reload() {
      await loadFolders(); clear(list);
      if (!state.folders.length) list.append(h('p', { class: 'muted' }, 'No folders yet.'));
      for (const f of state.folders) {
        list.append(h('div', { class: 'row between' }, h('span', {}, `${f.name} `, h('span', { class: 'muted small' }, `(${f.count})`)),
          h('span', { class: 'row' },
            h('button', { class: 'small', onclick: guard(async () => { const n = prompt('Rename folder', f.name); if (n) { await api('PATCH', `/api/folders/${f.id}`, { json: { name: n } }); await reload(); } }) }, 'Rename'),
            h('button', { class: 'small danger', onclick: guard(async () => { if (confirm(`Delete folder "${f.name}"? Its documents move to "No folder".`)) { await api('DELETE', `/api/folders/${f.id}`); await reload(); } }) }, 'Delete'))));
      }
    }
    reload();
    modal('Folders', h('div', { class: 'stack' }, h('p', { class: 'muted small' }, 'Folders only organise your own documents. They never give anyone access.'), list,
      h('div', { class: 'row' }, name, h('button', { class: 'primary', onclick: guard(async () => { if (name.value.trim()) { await api('POST', '/api/folders', { json: { name: name.value.trim() } }); name.value = ''; await reload(); } }) }, 'Add'))),
    (close) => [h('button', { onclick: () => { close(); route(); } }, 'Done')]);
  }

  // ---------- document detail ----------
  async function viewDocument(id) {
    let data;
    try { data = await api('GET', `/api/documents/${encodeURIComponent(id)}`); } catch (e) {
      mount(shell('docs', h('div', { class: 'card empty' }, h('h2', {}, 'Document not found'), h('p', {}, 'It may not exist, or you may not have access.'), h('a', { class: 'btn', href: '#/' }, 'Back to documents')))); return;
    }
    const d = data.document;
    const canEdit = d.myPermission === 'owner' || d.myPermission === 'edit';
    const owner = d.myPermission === 'owner';

    const versions = h('div', { class: 'tablewrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Version', 'File', 'Size', 'Uploaded', 'SHA-256', ''].map((x) => h('th', {}, x)))),
      h('tbody', {}, d.versions.map((v) => h('tr', {},
        h('td', {}, `v${v.version}`, v.version === d.currentVersion && h('span', { class: 'badge ok' }, 'current')),
        h('td', {}, v.fileName), h('td', {}, fmtSize(v.size)), h('td', {}, `${fmtDate(v.uploadedAt)} by ${v.uploadedBy}`),
        h('td', { class: 'mono' }, v.sha256.slice(0, 12) + '...'),
        h('td', {}, h('button', { class: 'small', onclick: guard(() => download(`/api/documents/${d.id}/download?version=${v.version}`, v.fileName)) }, 'Download')))))));

    const fileIn = h('input', { type: 'file', 'aria-label': 'New version file' });
    const newVer = canEdit && h('div', { class: 'row' }, fileIn, h('button', { onclick: guard(async () => {
      const file = fileIn.files[0]; if (!file) throw new Error('Choose a file first');
      await api('POST', `/api/documents/${d.id}/versions?name=${encodeURIComponent(file.name)}`, { body: file, headers: { 'content-type': 'application/octet-stream' } });
      toast('New version uploaded'); viewDocument(d.id);
    }) }, 'Upload new version'));

    mount(shell('docs', h('div', { class: 'stack' },
      h('a', { href: '#/' }, '< All documents'),
      h('div', { class: 'card stack' },
        h('div', { class: 'row between' }, h('h1', {}, d.name), h('span', { class: `badge ${d.myPermission}` }, d.myPermission === 'owner' ? 'You own this' : `You can ${d.myPermission}`)),
        h('div', { class: 'muted' }, `${d.fileName} · ${fmtSize(d.size)} · version ${d.currentVersion} · owner ${d.owner ? d.owner.name : '?'} · updated ${fmtDate(d.updatedAt)}`),
        d.description && h('p', {}, d.description),
        d.tags.length > 0 && h('div', { class: 'tags' }, d.tags.map((t) => h('span', { class: 'badge' }, t))),
        h('div', { class: 'row' },
          h('button', { class: 'primary', onclick: guard(() => download(`/api/documents/${d.id}/download`, d.fileName)) }, 'Download'),
          canEdit && h('button', { onclick: () => editMeta(d) }, 'Edit details'),
          owner && h('button', { class: 'danger', onclick: guard(async () => {
            if (!confirm('Move this document to trash? Everyone you shared it with loses access immediately.')) return;
            await api('DELETE', `/api/documents/${d.id}`); toast('Moved to trash. All sharing was removed.'); location.hash = '#/';
          }) }, 'Move to trash'))),
      h('div', { class: 'card stack' }, h('h2', {}, 'Versions'), versions, newVer),
      owner && sharingPanel(d),
      owner && activityPanel(d))));
  }

  function editMeta(d) {
    const name = h('input', { value: d.name, 'aria-label': 'Title' });
    const desc = h('textarea', { 'aria-label': 'Description' }); desc.value = d.description;
    const tags = h('input', { value: d.tags.join(', '), 'aria-label': 'Tags' });
    const folder = d.myPermission === 'owner' ? h('select', { 'aria-label': 'Folder' }, h('option', { value: '' }, 'No folder'), ...state.folders.map((x) => h('option', { value: x.id, selected: d.folderId === x.id }, x.name))) : null;
    if (d.myPermission === 'owner' && !state.folders.length) loadFolders();
    modal('Edit details', h('div', { class: 'stack' }, h('div', {}, h('label', {}, 'Title'), name), h('div', {}, h('label', {}, 'Description'), desc), h('div', {}, h('label', {}, 'Tags'), tags),
      folder && h('div', {}, h('label', {}, 'Folder'), folder)),
    (close) => [h('button', { class: 'primary', onclick: guard(async () => {
      const body = { name: name.value, description: desc.value, tags: tags.value };
      if (folder) body.folderId = folder.value || null;
      await api('PATCH', `/api/documents/${d.id}`, { json: body }); close(); toast('Saved'); viewDocument(d.id);
    }) }, 'Save'), h('button', { onclick: close }, 'Cancel')]);
  }

  // ---------- sharing ----------
  function sharingPanel(d) {
    const box = h('div', { class: 'card stack' });
    const grantsBox = h('div', { class: 'stack' });
    const suggestBox = h('div', { class: 'stack' });
    let picked = null;

    const q = h('input', { placeholder: 'Find a person by name or email', 'aria-label': 'Find a person', autocomplete: 'off' });
    const list = h('div', { class: 'picker-list', hidden: true });
    const pickedLabel = h('div', { class: 'small muted' }, 'Nobody selected');
    const perm = h('select', { 'aria-label': 'Permission' }, h('option', { value: 'read' }, 'Can read'), h('option', { value: 'edit' }, 'Can read and edit'));
    const exp = h('input', { type: 'date', min: inDays(1), 'aria-label': 'Access ends on' });
    const expHint = h('p', { class: 'hint' }, 'Optional for colleagues. Leave blank for no end date.');
    let timer;
    q.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(guard(async () => {
        const r = await api('GET', `/api/users/directory?q=${encodeURIComponent(q.value.trim())}`);
        clear(list); list.hidden = false;
        if (!r.users.length) list.append(h('div', { class: 'empty small' }, 'No matching people'));
        for (const u of r.users) list.append(h('button', { type: 'button', onclick: () => {
          picked = u; q.value = ''; list.hidden = true;
          pickedLabel.textContent = `${u.name} (${u.email})${u.isExternal ? ' - EXTERNAL, expiry required (max 30 days)' : ''}`;
          if (u.isExternal) { expHint.textContent = 'Required for external people: at most 30 days.'; if (!exp.value) exp.value = inDays(14); } else expHint.textContent = 'Optional for colleagues. Leave blank for no end date.';
          perm.querySelector('option[value=edit]').disabled = u.role === 'viewer'; if (u.role === 'viewer') perm.value = 'read';
        } }, h('span', {}, u.name, ' ', h('span', { class: 'muted small' }, u.email)), u.isExternal ? h('span', { class: 'badge external' }, 'external') : h('span', { class: 'badge' }, u.role)));
      }), 200);
    });

    async function loadGrants() {
      const r = await api('GET', `/api/documents/${d.id}/grants`);
      clear(grantsBox);
      const active = r.grants.filter((g) => g.status === 'active');
      grantsBox.append(h('h3', {}, `Who has access (${active.length})`));
      if (!active.length) grantsBox.append(h('p', { class: 'muted' }, 'Only you. This document is private.'));
      for (const g of active) {
        grantsBox.append(h('div', { class: 'row between' },
          h('div', {}, h('b', {}, g.grantee ? g.grantee.name : '?'), ' ', h('span', { class: 'muted small' }, g.grantee ? g.grantee.email : ''), ' ',
            h('span', { class: `badge ${g.permission}` }, g.permission), g.grantee && g.grantee.isExternal && h('span', { class: 'badge external' }, 'external'), g.viaSuggestion && h('span', { class: 'badge info' }, 'via assistant'),
            h('div', { class: 'muted small' }, `Granted ${fmtDay(g.grantedAt)}${g.expiresAt ? ` · ends ${fmtDate(g.expiresAt)}` : ' · no end date'}`)),
          h('button', { class: 'small danger', onclick: guard(async () => {
            if (!confirm(`Remove ${g.grantee ? g.grantee.name : 'this person'}'s access now?`)) return;
            await api('DELETE', `/api/documents/${d.id}/grants/${g.id}`); toast('Access removed immediately'); await loadGrants(); loadActivity();
          }) }, 'Remove access')));
      }
      const past = r.grants.filter((g) => g.status !== 'active').slice(0, 5);
      if (past.length) grantsBox.append(h('details', {}, h('summary', { class: 'muted small' }, `History (${r.grants.length - active.length} ended)`),
        past.map((g) => h('div', { class: 'small muted' }, `${g.grantee ? g.grantee.name : '?'} · ${g.permission} · ${g.status}`))));
    }

    const shareBtn = h('button', { class: 'primary', onclick: guard(async () => {
      if (!picked) throw new Error('Pick a person first');
      const body = { userId: picked.id, permission: perm.value };
      if (exp.value) body.expiresAt = dateInputToMs(exp.value);
      await api('POST', `/api/documents/${d.id}/grants`, { json: body });
      toast(`Shared with ${picked.name}`); picked = null; pickedLabel.textContent = 'Nobody selected'; exp.value = '';
      await loadGrants(); loadActivity();
    }) }, 'Share');

    const suggestBtn = h('button', { onclick: guard(async () => {
      const r = await api('POST', `/api/documents/${d.id}/ai/suggest`, { json: {} });
      renderSuggestions(r);
    }) }, 'Suggest who should see this');

    function renderSuggestions(r) {
      clear(suggestBox);
      suggestBox.append(h('div', { class: 'badge info' }, 'Suggestions only - nothing is shared until you confirm'));
      if (r.warning) suggestBox.append(h('p', { class: 'badge medium' }, r.warning));
      if (!r.candidates.length) { suggestBox.append(h('p', { class: 'muted' }, 'No suggestions for this document. Use the form above.')); return; }
      const rows = r.candidates.map((c) => {
        const cb = h('input', { type: 'checkbox', 'aria-label': `Share with ${c.name}` });
        const days = h('input', { type: 'date', min: inDays(1), value: r.suggestedExpiryDays ? inDays(r.suggestedExpiryDays) : '', 'aria-label': `Access ends for ${c.name}` });
        return { c, cb, days, node: h('div', { class: 'suggest' }, h('label', { class: 'row' }, cb, h('b', {}, c.name), h('span', { class: 'muted small' }, c.email), h('span', { class: 'badge read' }, 'read')),
          h('div', { class: 'small muted' }, `Why: ${c.reasons.join('; ')}`), h('div', {}, h('label', { class: 'small' }, 'Access ends (optional)'), days)) };
      });
      suggestBox.append(...rows.map((x) => x.node));
      suggestBox.append(h('div', { class: 'row' },
        h('button', { class: 'primary', onclick: guard(async () => {
          const chosen = rows.filter((x) => x.cb.checked);
          const reject = rows.filter((x) => !x.cb.checked).map((x) => x.c.userId);
          if (!chosen.length && !confirm('Reject all suggestions?')) return;
          await api('POST', `/api/documents/${d.id}/ai/suggestions/${r.suggestionId}/decision`, { json: { accept: chosen.map((x) => ({ userId: x.c.userId, permission: 'read', ...(x.days.value ? { expiresAt: dateInputToMs(x.days.value) } : {}) })), reject } });
          clear(suggestBox); toast(chosen.length ? `Shared with ${chosen.length} confirmed ${chosen.length === 1 ? 'person' : 'people'}` : 'Suggestions rejected'); await loadGrants(); loadActivity();
        }) }, 'Confirm selected'),
        h('span', { class: 'hint' }, 'Unticked people are recorded as rejected.')));
    }

    box.append(h('h2', {}, 'Sharing'),
      h('div', { class: 'stack' }, h('div', { class: 'picker' }, q, list), pickedLabel,
        h('div', { class: 'grid cols-2' }, h('div', {}, h('label', {}, 'Permission'), perm), h('div', {}, h('label', {}, 'Access ends on'), exp, expHint)),
        h('div', { class: 'row' }, shareBtn, suggestBtn)),
      suggestBox, grantsBox);
    loadGrants().catch((e) => toast(e.message, 'error'));
    return box;
  }

  let loadActivity = () => {};
  function activityPanel(d) {
    const body = h('div', { class: 'tablewrap' });
    loadActivity = guard(async () => {
      const r = await api('GET', `/api/documents/${d.id}/activity`);
      clear(body);
      if (!r.activity.length) { body.append(h('p', { class: 'muted' }, 'No activity yet.')); return; }
      body.append(h('table', {}, h('thead', {}, h('tr', {}, ['When', 'Who', 'What', 'Result'].map((x) => h('th', {}, x)))),
        h('tbody', {}, r.activity.map((a) => h('tr', { class: a.outcome === 'denied' ? 'denied-row' : '' },
          h('td', {}, fmtDate(a.ts)), h('td', {}, a.actor || 'unknown'), h('td', {}, a.action.replace('document.', '').replace('.', ' ')),
          h('td', {}, h('span', { class: `badge ${a.outcome}` }, a.outcome === 'denied' ? 'refused' : a.outcome)))))));
    });
    loadActivity();
    return h('div', { class: 'card stack' }, h('h2', {}, 'Who opened this, and when'), h('p', { class: 'muted small' }, 'Every view, download, change and refused attempt on this document, from the tamper-evident audit trail.'), body);
  }

  // ---------- trash ----------
  async function viewTrash() {
    const box = h('div', {});
    async function load() {
      const r = await api('GET', '/api/trash'); clear(box);
      if (!r.documents.length) box.append(h('div', { class: 'empty' }, 'Trash is empty.'));
      for (const d of r.documents) box.append(h('div', { class: 'doc-item' }, h('div', { class: 'doc-main' }, h('div', { class: 'doc-title' }, d.name),
        h('div', { class: 'muted small' }, `Deleted ${ago(d.deletedAt)} · removed permanently on ${fmtDay(d.purgeAt)}`)),
      h('div', { class: 'row' },
        h('button', { class: 'small', onclick: guard(async () => { await api('POST', `/api/documents/${d.id}/restore`, { json: {} }); toast('Restored as private. Share it again if needed.'); load(); }) }, 'Restore'),
        h('button', { class: 'small danger', onclick: guard(async () => { if (confirm('Permanently delete this document and every version? This cannot be undone.')) { await api('DELETE', `/api/documents/${d.id}/purge`); toast('Permanently deleted'); load(); } }) }, 'Delete forever'))));
    }
    mount(shell('trash', h('div', { class: 'card stack' }, h('h1', {}, 'Trash'), h('p', { class: 'muted small' }, 'Trashed documents are invisible to everyone but you, and all sharing was removed. They are deleted for good after the retention period.'), box)));
    guard(load)();
  }

  // ---------- admin ----------
  async function viewAdmin(tab = 'overview') {
    const body = h('div', {});
    const tabs = [['overview', 'Overview'], ['users', 'Users'], ['documents', 'Documents'], ['access', 'Access'], ['audit', 'Audit trail']];
    mount(shell('admin', h('div', { class: 'stack' }, h('h1', {}, 'Administration'),
      h('div', { class: 'tabs', role: 'tablist' }, tabs.map(([k, l]) => h('button', { role: 'tab', class: tab === k ? 'active' : '', 'aria-selected': tab === k, onclick: () => viewAdmin(k) }, l))),
      body)));
    await guard(async () => {
      if (tab === 'overview') await adminOverview(body);
      else if (tab === 'users') await adminUsers(body);
      else if (tab === 'documents') await adminDocuments(body);
      else if (tab === 'access') await adminAccess(body);
      else await adminAudit(body);
    })();
  }

  async function adminOverview(body) {
    const r = await api('GET', '/api/admin/alerts');
    body.append(h('div', { class: 'grid cols-2' }, [['users', 'Active users'], ['documents', 'Documents'], ['activeGrants', 'Active shares'], ['deniedLastDay', 'Refused (24 h)']].map(([k, l]) => h('div', { class: 'card stat' }, h('b', {}, r.stats[k]), h('span', { class: 'muted' }, l)))),
      h('div', { class: 'card stack' }, h('h2', {}, 'Worth noticing'),
        !r.alerts.length && h('p', { class: 'muted' }, 'Nothing unusual right now.'),
        r.alerts.map((a) => h('div', { class: `alert ${a.severity}` }, h('b', {}, a.severity.toUpperCase()), h('span', {}, a.message)))),
      h('div', { class: `card ${r.auditOk ? '' : 'alert critical'}` }, h('b', {}, r.auditOk ? 'Audit trail integrity: verified' : 'Audit trail integrity: FAILED')));
  }

  async function adminUsers(body) {
    const r = await api('GET', '/api/admin/users');
    const rows = r.users.map((u) => h('tr', {},
      h('td', {}, h('b', {}, u.name), h('div', { class: 'muted small' }, u.email)),
      h('td', {}, h('span', { class: `badge ${u.role}` }, u.role), u.isExternal && h('span', { class: 'badge external' }, 'external')),
      h('td', {}, u.department || '-'),
      h('td', {}, u.disabled ? h('span', { class: 'badge bad' }, 'disabled') : h('span', { class: 'badge ok' }, 'active')),
      h('td', {}, h('div', { class: 'row' },
        h('select', { 'aria-label': `Role for ${u.name}`, disabled: u.isExternal, onchange: guard(async (e) => { await api('PATCH', `/api/admin/users/${u.id}`, { json: { role: e.target.value } }); toast('Role updated'); viewAdmin('users'); }) },
          ...['admin', 'owner', 'viewer'].map((x) => h('option', { value: x, selected: u.role === x }, x))),
        h('button', { class: `small ${u.disabled ? '' : 'danger'}`, onclick: guard(async () => {
          if (!u.disabled && !confirm(`Disable ${u.name}? They are signed out immediately.`)) return;
          await api('PATCH', `/api/admin/users/${u.id}`, { json: { disabled: !u.disabled } }); toast(u.disabled ? 'Account enabled' : 'Account disabled'); viewAdmin('users');
        }) }, u.disabled ? 'Enable' : 'Disable'),
        h('button', { class: 'small', onclick: guard(async () => {
          if (!confirm(`Reset ${u.name}'s password? They are signed out and must choose a new one.`)) return;
          const t = await api('POST', `/api/admin/users/${u.id}/reset-password`, { json: {} }); showSecret(`Temporary password for ${u.name}`, t.temporaryPassword);
        }) }, 'Reset password')))));
    body.append(h('div', { class: 'card stack' }, h('div', { class: 'row between' }, h('h2', {}, `People (${r.users.length})`), h('button', { class: 'primary small', onclick: createUserModal }, 'Add person')),
      h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Person', 'Role', 'Department', 'Status', 'Actions'].map((x) => h('th', {}, x)))), h('tbody', {}, rows)))));
  }

  function showSecret(title, secret) {
    modal(title, h('div', { class: 'stack' }, h('p', { class: 'muted' }, 'Shown once. Share it through a secure channel. The person must change it at first sign-in.'), h('div', { class: 'secret' }, secret)),
      (close) => [h('button', { class: 'primary', onclick: close }, 'Done')]);
  }

  function createUserModal() {
    const name = h('input', { 'aria-label': 'Full name' }); const em = h('input', { type: 'email', 'aria-label': 'Email' }); const dept = h('input', { 'aria-label': 'Department', placeholder: 'e.g. HR, Finance, Legal, Engineering' });
    const role = h('select', { 'aria-label': 'Role' }, h('option', { value: 'owner' }, 'Document owner'), h('option', { value: 'viewer' }, 'Viewer (read-only)'), h('option', { value: 'admin' }, 'Administrator'));
    const external = h('input', { type: 'checkbox', 'aria-label': 'External person' });
    external.addEventListener('change', () => { if (external.checked) role.value = 'viewer'; });
    modal('Add person', h('div', { class: 'stack' }, h('div', {}, h('label', {}, 'Full name'), name), h('div', {}, h('label', {}, 'Email'), em), h('div', {}, h('label', {}, 'Department'), dept), h('div', {}, h('label', {}, 'Role'), role),
      h('label', { class: 'row' }, external, 'External person (outside the company; viewer only; access always expires)')),
    (close) => [h('button', { class: 'primary', onclick: guard(async () => {
      const r = await api('POST', '/api/admin/users', { json: { name: name.value, email: em.value, department: dept.value || undefined, role: role.value, isExternal: external.checked } });
      close(); showSecret(`Temporary password for ${r.user.name}`, r.temporaryPassword); viewAdmin('users');
    }) }, 'Create'), h('button', { onclick: close }, 'Cancel')]);
  }

  async function adminDocuments(body) {
    const r = await api('GET', '/api/admin/documents');
    body.append(h('div', { class: 'card stack' }, h('h2', {}, `All documents (${r.documents.length})`),
      h('p', { class: 'muted small' }, 'Metadata only. Administrators cannot open file contents.'),
      h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Document', 'Owner', 'Size', 'Version', 'Shares', 'Updated'].map((x) => h('th', {}, x)))),
        h('tbody', {}, r.documents.map((d) => h('tr', {}, h('td', {}, d.name, d.inTrash && h('span', { class: 'badge bad' }, 'trash')), h('td', {}, d.owner.name), h('td', {}, fmtSize(d.size)), h('td', {}, `v${d.version}`),
          h('td', {}, `${d.activeGrants}`, d.externalGrants > 0 && h('span', { class: 'badge external' }, `${d.externalGrants} external`)), h('td', {}, fmtDate(d.updatedAt)))))))));
  }

  async function adminAccess(body) {
    const r = await api('GET', '/api/admin/grants');
    body.append(h('div', { class: 'card stack' }, h('h2', {}, `Active access grants (${r.grants.length})`),
      h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Document', 'Person', 'Permission', 'Granted', 'Ends', ''].map((x) => h('th', {}, x)))),
        h('tbody', {}, r.grants.map((g) => h('tr', {}, h('td', {}, g.documentName, h('div', { class: 'muted small' }, `owner ${g.owner}`)),
          h('td', {}, g.grantee ? g.grantee.name : '?', g.grantee && g.grantee.isExternal && h('span', { class: 'badge external' }, 'external')), h('td', {}, h('span', { class: `badge ${g.permission}` }, g.permission)),
          h('td', {}, fmtDay(g.grantedAt)), h('td', {}, g.expiresAt ? fmtDay(g.expiresAt) : 'never'),
          h('td', {}, h('button', { class: 'small danger', onclick: guard(async () => { if (confirm('Revoke this access now?')) { await api('POST', `/api/admin/grants/${g.id}/revoke`, { json: {} }); toast('Revoked'); viewAdmin('access'); } }) }, 'Revoke')))))))));
  }

  async function adminAudit(body) {
    const f = { category: '', denied: false, actor: '' };
    const box = h('div', { class: 'tablewrap' });
    const verifyBox = h('div', {});
    const cat = h('select', { 'aria-label': 'Category' }, ...[['', 'Everything'], ['access', 'Document access'], ['permission', 'Permission changes'], ['auth', 'Sign-ins']].map(([v, l]) => h('option', { value: v }, l)));
    const denied = h('input', { type: 'checkbox', id: 'denied' });
    const actor = h('input', { placeholder: 'Filter by email', 'aria-label': 'Actor email' });
    let entries = [];
    async function load() {
      const qs = new URLSearchParams({ limit: '200' });
      if (f.category) qs.set('category', f.category); if (f.denied) qs.set('denied', '1'); if (f.actor) qs.set('actor', f.actor);
      entries = (await api('GET', `/api/admin/audit?${qs}`)).entries; clear(box);
      if (!entries.length) { box.append(h('p', { class: 'muted' }, 'No entries.')); return; }
      box.append(h('table', {}, h('thead', {}, h('tr', {}, ['#', 'When', 'Who', 'Action', 'Result', 'Target', 'IP', 'Details'].map((x) => h('th', {}, x)))),
        h('tbody', {}, entries.map((e) => h('tr', { class: e.outcome === 'denied' ? 'denied-row' : '' }, h('td', {}, e.seq), h('td', {}, fmtDate(e.ts)), h('td', {}, e.actor_email || '-'), h('td', {}, e.action),
          h('td', {}, h('span', { class: `badge ${e.outcome}` }, e.outcome)), h('td', { class: 'mono' }, e.target_id ? `${e.target_type}:${String(e.target_id).slice(0, 8)}` : '-'), h('td', {}, e.ip || '-'),
          h('td', { class: 'mono' }, JSON.stringify(e.details).slice(0, 160)))))));
    }
    cat.addEventListener('change', () => { f.category = cat.value; guard(load)(); });
    denied.addEventListener('change', () => { f.denied = denied.checked; guard(load)(); });
    let t; actor.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { f.actor = actor.value.trim(); guard(load)(); }, 300); });

    body.append(h('div', { class: 'card stack' }, h('h2', {}, 'Audit trail'),
      h('p', { class: 'muted small' }, 'Append-only and hash-chained. If any past entry is altered or removed, verification fails.'),
      h('div', { class: 'row' }, h('button', { onclick: guard(async () => {
        const r = await api('GET', '/api/admin/audit/verify'); clear(verifyBox);
        verifyBox.append(h('div', { class: `alert ${r.ok ? 'info' : 'critical'}` }, r.ok ? `Verified: ${r.checked} entries intact. Head ${r.head ? r.head.hash.slice(0, 16) : '-'}... (seq ${r.head ? r.head.seq : 0})` : `FAILED at entry ${r.brokenAtSeq}: ${r.reason}`));
      }) }, 'Verify integrity'), h('button', { onclick: () => {
        const blob = new Blob([JSON.stringify(entries, null, 2)], { type: 'application/json' });
        const href = URL.createObjectURL(blob); const a = h('a', { href, download: 'trustvault-audit.json' }); document.body.append(a); a.click(); a.remove();
      } }, 'Export shown entries')), verifyBox,
      h('div', { class: 'grid cols-2' }, cat, actor), h('label', { class: 'row', for: 'denied' }, denied, 'Only refused attempts'), box));
    await load();
  }

  // ---------- router ----------
  function route() {
    const hash = location.hash || '#/';
    const [, a, b] = hash.split('/');
    if (!state.user) { if (a !== 'login') { location.hash = '#/login'; return; } return viewLogin(); }
    if (state.user.mustChangePassword && a !== 'password') { location.hash = '#/password'; return; }
    if (a === 'login') { location.hash = isAdmin() ? '#/admin' : '#/'; return; }
    if (a === 'password') return viewPassword();
    if (a === 'account') return viewAccount();
    if (a === 'admin') { if (!isAdmin()) { location.hash = '#/'; return; } return viewAdmin(); }
    if (a === 'trash') { if (!isOwner()) { location.hash = '#/'; return; } return viewTrash(); }
    if (a === 'doc' && b) return viewDocument(b);
    if (isAdmin()) { location.hash = '#/admin'; return; }
    return viewDocuments();
  }

  window.addEventListener('hashchange', route);
  (async () => {
    try { const me = await api('GET', '/api/auth/me'); state.user = me.user; state.csrf = me.csrfToken; } catch { state.user = null; }
    route();
  })();
})();
