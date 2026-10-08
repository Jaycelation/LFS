'use strict';
(() => {
  // ---------------------------------------------------------------------------
  // Basics
  // ---------------------------------------------------------------------------
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

  const ls = {
    get(k, d) {
      try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (_) { return d; }
    },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (_) { /* private mode */ } },
    del(k) { try { localStorage.removeItem(k); } catch (_) { /* ignore */ } },
  };

  const state = {
    info: null,
    identity: ls.get('lfs.identity', null), // encrypted identity file
    sk: null,                                // secret key, memory only
    token: null,
    user: null,
    users: [], files: [], grants: [], audit: [], publicFiles: [],
    view: 'public',
    authTab: 'login',
    lang: ls.get('lfs.lang', (navigator.language || '').startsWith('vi') ? 'vi' : 'en'),
    mutual: ls.get('lfs.mutual', true),
    authLog: [],
    openGrant: null,
    createdGrant: null,
    shareFileId: null,
    modalFileId: null,
    modalTab: 'file',
    pendingFile: null,
    prefillUploadKey: '',
    showUpload: false,
    navOpen: false,
    busy: false,
  };

  function t(key, vars) {
    let s = (I18N[state.lang] && I18N[state.lang][key]) || I18N.en[key] || key;
    if (vars) for (const [k, v] of Object.entries(vars)) s = s.split('{' + k + '}').join(v);
    return s;
  }

  const fresh = () => ({ nonce: LFS.randomHex(16), ts: Date.now() });
  const pins = () => ls.get('lfs.pins', {});
  const pinnedKey = () => pins()[location.origin] || null;
  function pin(key) {
    const p = pins();
    p[location.origin] = key;
    ls.set('lfs.pins', p);
  }

  function fmtBytes(n) {
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + ' ' + u[i];
  }
  const fmtDate = (ms) => new Date(ms).toLocaleString(state.lang === 'vi' ? 'vi-VN' : 'en-US',
    { dateStyle: 'short', timeStyle: 'short' });
  const initials = (name) => (name || '?').slice(0, 2).toUpperCase();

  const ICON = {
    lock: 'M7 11V8a5 5 0 0 1 10 0v3M6 11h12v9H6z',
    globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zm-9 9h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9z',
    check: 'M5 12.5l4.5 4.5L19 7',
    clock: 'M12 7v5l3 2M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z',
    up: 'M12 16V4m0 0l-5 5m5-5l5 5M4 16v4h16v-4',
    down: 'M12 4v12m0 0l-5-5m5 5l5-5M4 16v4h16v-4',
  };
  const icon = (name, size = 16) => `<svg class="ico" viewBox="0 0 24 24" width="${size}" height="${size}" aria-hidden="true"><path d="${ICON[name]}" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

  // ---------------------------------------------------------------------------
  // API
  // ---------------------------------------------------------------------------
  class ApiError extends Error {
    constructor(message, code) { super(message); this.code = code; }
  }

  async function api(method, url, body) {
    const headers = { Accept: 'application/json' };
    if (state.token) headers.Authorization = 'Bearer ' + state.token;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let r;
    try {
      r = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch (_) {
      throw new ApiError(t('err.network'), 'network');
    }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      if (r.status === 401 && j.error === 'unauthenticated' && state.user) {
        resetSession();
        state.view = 'login';
        render();
      }
      throw new ApiError(j.message || j.error || 'HTTP ' + r.status, j.error);
    }
    return j;
  }

  function errText(e) {
    if (e && e.code === 'grant_not_active') {
      const m = /is (\w+)/.exec(e.message || '');
      return t('err.grant_not_active', { detail: m ? t('status.' + m[1]) : '' });
    }
    if (e && e.code && I18N[state.lang]['err.' + e.code]) return t('err.' + e.code);
    return (e && e.message) || String(e);
  }

  // ---------------------------------------------------------------------------
  // UI helpers
  // ---------------------------------------------------------------------------
  function toast(msg, kind = 'ok') {
    const el = document.createElement('div');
    el.className = 'toast ' + kind;
    el.textContent = msg;
    $('#toasts').appendChild(el);
    setTimeout(() => el.classList.add('out'), 3800);
    setTimeout(() => el.remove(), 4300);
  }
  const toastErr = (e) => toast(errText(e), 'err');

  // Run fn while showing a busy state on the button; never double-submit.
  async function busy(btn, fn) {
    if (state.busy) return;
    state.busy = true;
    const label = btn ? btn.innerHTML : '';
    if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spin"></span>' + esc(t('auth.working')); }
    // Let the browser paint before CPU-heavy crypto (PBKDF2).
    await new Promise((r) => setTimeout(r, 30));
    try {
      return await fn();
    } catch (e) {
      toastErr(e);
    } finally {
      state.busy = false;
      if (btn && btn.isConnected) { btn.disabled = false; btn.innerHTML = label; }
    }
  }

  function openModal(html, wide) {
    const m = $('#modal');
    m.innerHTML = `<div class="modal-dialog ${wide ? 'wide' : ''}"><div class="modal-content">${html}</div></div>`;
    m.classList.remove('hidden');
    document.body.classList.add('modal-open');
  }
  function closeModal() {
    $('#modal').classList.add('hidden');
    $('#modal').innerHTML = '';
    document.body.classList.remove('modal-open');
    state.modalFileId = null;
  }

  function statusBadge(status) {
    const cls = { active: 'success', awaiting_approvals: 'warning', awaiting_acceptance: 'warning' }[status] || 'secondary';
    return `<span class="badge ${cls}">${esc(t('status.' + status))}</span>`;
  }

  async function copy(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      // Clipboard API needs a secure context; fall back to a temporary textarea.
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    if (btn) {
      const old = btn.textContent;
      btn.textContent = t('keys.copied');
      setTimeout(() => { btn.textContent = old; }, 1500);
    }
  }

  function triggerDownload(url, name) {
    const a = document.createElement('a');
    a.href = url;
    a.download = name || '';
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  // ---------------------------------------------------------------------------
  // Identity & authentication
  // ---------------------------------------------------------------------------
  function logStep(key, ok = true, extra = '') {
    state.authLog.push({ text: t(key), ok, extra });
    const el = $('#authLog');
    if (el) el.innerHTML = renderAuthLog();
  }

  function unlock(passphrase) {
    try {
      state.sk = LFS.unlockIdentityFile(state.identity, passphrase);
    } catch (e) {
      throw new ApiError(t('err.wrong_passphrase'), 'wrong_passphrase');
    }
    logStep('auth.log.unlock');
  }

  async function register() {
    const id = state.identity;
    const obj = { username: id.username, publicKey: id.publicKey, server: state.info.serverPublicKey };
    const r = await api('POST', '/api/register', { ...obj, signature: LFS.sign(state.sk, 'register', obj) });
    logStep('auth.log.register');
    return r.user;
  }

  async function login() {
    const username = state.identity.username;
    const clientNonce = LFS.randomHex(32);
    logStep('auth.log.nonce', true, clientNonce.slice(0, 16) + '…');
    const c = await api('POST', '/api/auth/challenge', { username, clientNonce });
    logStep('auth.log.challenge', true, c.serverNonce.slice(0, 16) + '…');

    if (state.mutual) {
      const pinned = pinnedKey();
      if (!pinned) {
        pin(c.serverPublicKey);
        logStep('auth.log.pinned', true, LFS.fingerprint(c.serverPublicKey));
      } else if (pinned !== c.serverPublicKey) {
        logStep('err.server_key_changed', false);
        throw new ApiError(t('err.server_key_changed'), 'server_key_changed');
      }
      const sObj = { challengeId: c.challengeId, username, clientNonce, serverNonce: c.serverNonce };
      if (!LFS.verify(pinnedKey(), 'auth-server', sObj, c.serverSignature)) {
        logStep('err.server_sig', false);
        throw new ApiError(t('err.server_sig'), 'server_sig');
      }
      logStep('auth.log.serverok');
    } else {
      logStep('auth.log.oneway');
    }

    const obj = {
      challengeId: c.challengeId, username, clientNonce,
      serverNonce: c.serverNonce, server: c.serverPublicKey,
    };
    const signature = LFS.sign(state.sk, 'auth-client', obj);
    logStep('auth.log.sign', true, signature.slice(0, 16) + '…');
    const r = await api('POST', '/api/auth/verify', { challengeId: c.challengeId, signature });
    logStep('auth.log.session');
    state.token = r.token;
    state.user = r.user;
    state.view = 'files';
    await loadAll();
    render();
    toast(`${state.user.username} ✔`);
  }

  function resetSession() {
    state.token = null;
    state.user = null;
    state.sk = null;
    state.openGrant = null;
    state.createdGrant = null;
  }

  async function logout() {
    try { await api('POST', '/api/auth/logout', {}); } catch (_) { /* ignore */ }
    resetSession();
    state.authLog = [];
    state.view = 'public';
    await loadPublic();
    render();
  }

  // ---------------------------------------------------------------------------
  // Data
  // ---------------------------------------------------------------------------
  async function loadPublic() {
    try {
      state.publicFiles = (await api('GET', '/api/public/files')).files;
    } catch (_) {
      state.publicFiles = [];
    }
  }

  async function loadAll() {
    const [u, f, g] = await Promise.all([api('GET', '/api/users'), api('GET', '/api/files'), api('GET', '/api/grants')]);
    state.users = u.users;
    state.files = f.files;
    state.grants = g.grants;
    if (state.user.role === 'admin') state.audit = (await api('GET', '/api/admin/audit?limit=300')).events;
    if (state.openGrant) {
      const fresher = state.grants.find((x) => x.id === state.openGrant.id);
      if (fresher) state.openGrant = fresher;
    }
  }

  async function refresh() {
    try {
      if (state.user) {
        await loadAll();
        renderDynamic();
      } else if (state.view === 'public') {
        await loadPublic();
        const el = $('#publicTiles');
        if (el) el.innerHTML = renderPublicTiles();
      }
    } catch (_) { /* transient */ }
  }

  // ---------------------------------------------------------------------------
  // Render: shell (CTFd-style navbar + jumbotron + container)
  // ---------------------------------------------------------------------------
  const todoCount = () => state.grants.filter((g) => g.me.canApprove || g.me.canAccept).length;

  function renderNavbar() {
    const links = state.user
      ? [['files', 'nav.files'], ['keys', 'nav.keys'], ['identity', 'nav.identity']]
        .concat(state.user.role === 'admin' ? [['admin', 'nav.admin']] : [])
      : [['public', 'nav.public']];
    const todo = state.user ? todoCount() : 0;
    const right = state.user
      ? `<li><span class="nav-user"><span class="avatar">${esc(initials(state.user.username))}</span>${esc(state.user.username)}${state.user.role === 'admin' ? ' <span class="badge light">admin</span>' : ''}</span></li>
         <li><button type="button" class="nav-link" data-action="logout">${esc(t('btn.logout'))}</button></li>`
      : `<li><button type="button" class="nav-link ${state.view === 'login' ? 'active' : ''}" data-view="login">${esc(t('nav.login'))}</button></li>`;
    $('#navbar').innerHTML = `
      <div class="container nav-inner">
        <button type="button" class="navbar-brand" data-view="${state.user ? 'files' : 'public'}">
          ${icon('up', 18)}<span>${esc(state.info ? state.info.name : 'Local File Share')}</span>
        </button>
        <button type="button" class="nav-toggle" data-action="toggle-nav" aria-label="Menu">☰</button>
        <div class="nav-collapse ${state.navOpen ? 'open' : ''}">
          <ul class="nav-left">
            ${links.map(([v, k]) => `<li><button type="button" class="nav-link ${state.view === v ? 'active' : ''}" data-view="${v}">${esc(t(k))}${v === 'keys' && todo ? ` <span class="badge danger pill">${todo}</span>` : ''}</button></li>`).join('')}
          </ul>
          <ul class="nav-right">
            <li class="lang">${['vi', 'en'].map((l) => `<button type="button" class="${state.lang === l ? 'on' : ''}" data-lang="${l}">${l.toUpperCase()}</button>`).join('')}</li>
            ${right}
          </ul>
        </div>
      </div>`;
    document.documentElement.lang = state.lang;
    if (state.info) {
      $('#footerMode').textContent = t('mode.' + state.info.networkMode);
    }
  }

  function jumbotron(title, sub) {
    return `<div class="jumbotron"><div class="container"><h1>${esc(title)}</h1>${sub ? `<p>${sub}</p>` : ''}</div></div>`;
  }

  function render() {
    renderNavbar();
    const root = $('#root');
    if (!state.info) {
      root.innerHTML = `<div class="container center"><span class="spin"></span></div>`;
      return;
    }
    if (!state.user && !['public', 'login'].includes(state.view)) state.view = 'public';
    const views = {
      public: () => jumbotron(t('nav.public'), esc(t('public.sub'))) + `<div class="container">${renderPublic()}</div>`,
      login: () => jumbotron(t('nav.login'), esc(t('app.tagline'))) + `<div class="container">${renderAuth()}</div>`,
      files: () => jumbotron(t('nav.files'), esc(t('files.sub'))) + `<div class="container">${renderFiles()}</div>`,
      keys: () => jumbotron(t('nav.keys'), esc(t('keys.sub'))) + `<div class="container">${renderKeys()}</div>`,
      identity: () => jumbotron(t('nav.identity'), `<code>${esc(LFS.fingerprint(state.identity.publicKey))}</code>`) + `<div class="container">${renderIdentity()}</div>`,
      admin: () => jumbotron(t('nav.admin')) + `<div class="container">${renderAdmin()}</div>`,
    };
    root.innerHTML = (views[state.view] || views.public)();
    if (state.view === 'keys') syncCreateForm();
    if (state.modalFileId) renderFileModal();
  }

  // Re-render only the data-driven parts so typing in forms is not interrupted.
  function renderDynamic() {
    if (!state.user) return;
    const map = {
      fileTiles: renderFileTiles, keysTodo: renderTodo, keysAll: renderGrantsTable,
      grantDetail: renderGrantDetail, adminUsers: renderUsersTable, adminAudit: renderAuditTable,
    };
    for (const [id, fn] of Object.entries(map)) {
      const el = document.getElementById(id);
      if (el) el.innerHTML = fn();
    }
    renderNavbar();
  }

  // ---------------------------------------------------------------------------
  // Public (no login) — like a plain http.server listing
  // ---------------------------------------------------------------------------
  function renderPublicTiles() {
    if (!state.publicFiles.length) return `<p class="empty">${esc(t('public.empty'))}</p>`;
    return `<div class="tiles">${state.publicFiles.map((f) => `
      <a class="tile ok" href="${esc(f.url)}" download="${esc(f.name)}" title="SHA-256 ${esc(f.sha256)}">
        <span class="tile-flag">${icon('globe', 14)}</span>
        <span class="tile-name">${esc(f.name)}</span>
        <span class="tile-value">${esc(fmtBytes(f.size))}</span>
        <span class="tile-sub">${esc(f.owner)}</span>
      </a>`).join('')}</div>`;
  }

  function renderPublic() {
    return `
      <div class="toolbar">
        <span class="muted">${esc(t('public.hint'))}</span>
        <button type="button" class="btn btn-outline-secondary btn-sm" data-view="login">${esc(t('nav.login'))} →</button>
      </div>
      <div id="publicTiles">${renderPublicTiles()}</div>`;
  }

  // ---------------------------------------------------------------------------
  // Login / identity
  // ---------------------------------------------------------------------------
  function renderAuthLog() {
    if (!state.authLog.length) return '';
    return `<h5>${esc(t('auth.log'))}</h5><ol class="steps">${state.authLog.map((s) => `
      <li class="${s.ok ? 'ok' : 'bad'}"><span>${esc(s.text)}</span>${s.extra ? `<code>${esc(s.extra)}</code>` : ''}</li>`).join('')}</ol>`;
  }

  function renderServerCard() {
    const info = state.info;
    const pinned = pinnedKey();
    let pinHtml;
    if (!pinned) pinHtml = `<div class="alert info">${esc(t('auth.pin.none'))}</div>`;
    else if (pinned === info.serverPublicKey) pinHtml = `<div class="alert success">✔ ${esc(t('auth.pin.ok'))}</div>`;
    else {
      pinHtml = `<div class="alert danger">${esc(t('auth.pin.bad'))}
        <div class="mono small">pinned: ${esc(LFS.fingerprint(pinned))}</div></div>
        <button type="button" class="btn btn-danger btn-sm" data-action="repin">${esc(t('auth.repin'))}</button>`;
    }
    return `
      <div class="card">
        <div class="card-header">${esc(t('auth.server'))}: <b>${esc(info.name)}</b> <span class="badge ${info.networkMode === 'internal' ? 'info' : 'warning'}">${esc(t('mode.' + info.networkMode))}</span></div>
        <div class="card-body">
          <label class="form-label">${esc(t('auth.fp'))}</label>
          <div class="fp-box">${esc(info.fingerprint)}</div>
          ${pinHtml}
          <label class="check">
            <input type="checkbox" id="mutual" ${state.mutual ? 'checked' : ''}>
            <span>${esc(t('auth.mutual'))}<small>${esc(t('auth.mutual.hint'))}</small></span>
          </label>
        </div>
      </div>`;
  }

  function renderAuth() {
    const id = state.identity;
    const tabs = id ? [] : ['create', 'import'];
    const tab = id ? 'login' : (tabs.includes(state.authTab) ? state.authTab : 'create');
    let body;
    if (tab === 'login') {
      body = `
        <div class="identity-pill">
          <span class="avatar lg">${esc(initials(id.username))}</span>
          <div><b>${esc(id.username)}</b><div class="mono small muted">${esc(LFS.fingerprint(id.publicKey))}</div></div>
        </div>
        <form id="formLogin" autocomplete="off">
          <label class="form-label">${esc(t('auth.passphrase'))}</label>
          <input class="form-control" type="password" name="pass" required autofocus>
          <div class="row-btns">
            <button class="btn btn-primary" type="submit" data-mode="login">${esc(t('auth.btn.login'))}</button>
            <button class="btn btn-outline-secondary" type="submit" data-mode="register">${esc(t('auth.btn.register'))}</button>
          </div>
        </form>
        <button type="button" class="link" data-action="forget">${esc(t('auth.btn.other'))}</button>`;
    } else if (tab === 'create') {
      body = `
        <p class="muted small">${esc(t('auth.create.hint'))}</p>
        <form id="formCreate" autocomplete="off">
          <label class="form-label">${esc(t('auth.username'))}</label>
          <input class="form-control" name="username" required pattern="[a-zA-Z0-9_.\\-]{3,32}" placeholder="alice" autofocus>
          <small class="form-text">${esc(t('auth.username.hint'))}</small>
          <label class="form-label">${esc(t('auth.passphrase'))}</label>
          <input class="form-control" type="password" name="pass" required minlength="8">
          <label class="form-label">${esc(t('auth.passphrase2'))}</label>
          <input class="form-control" type="password" name="pass2" required minlength="8">
          <div class="row-btns"><button class="btn btn-primary" type="submit">${esc(t('auth.btn.create'))}</button></div>
        </form>`;
    } else {
      body = `
        <form id="formImport" autocomplete="off">
          <label class="form-label">${esc(t('auth.file'))}</label>
          <input class="form-control" type="file" name="file" accept=".json,application/json" required>
          <label class="form-label">${esc(t('auth.passphrase'))}</label>
          <input class="form-control" type="password" name="pass" required>
          <div class="row-btns"><button class="btn btn-primary" type="submit">${esc(t('auth.btn.import'))}</button></div>
        </form>`;
    }
    return `
      <div class="auth-grid">
        <div class="card">
          ${tabs.length
            ? `<ul class="nav-tabs">${tabs.map((x) => `<li><button type="button" class="${x === tab ? 'active' : ''}" data-authtab="${x}">${esc(t('auth.tab.' + x))}</button></li>`).join('')}</ul>`
            : `<div class="card-header">${esc(t('auth.identity'))}</div>`}
          <div class="card-body">
            ${body}
            <div id="authLog">${renderAuthLog()}</div>
          </div>
        </div>
        ${renderServerCard()}
      </div>`;
  }

  // ---------------------------------------------------------------------------
  // Files — tiles grouped by owner, like CTFd's challenge board
  // ---------------------------------------------------------------------------
  function myAccess(f) {
    if (!f.protected) return 'public';
    if (f.owner === state.user.username) return 'owner';
    if (f.canDownloadDirectly) return 'member';
    if (f.myGrants.some((g) => g.status === 'active')) return 'key';
    if (f.myGrants.some((g) => g.status.startsWith('awaiting'))) return 'pending';
    return 'none';
  }

  function renderFileTiles() {
    if (!state.files.length) return `<p class="empty">${esc(t('files.empty'))}</p>`;
    const groups = {};
    for (const f of state.files) (groups[f.owner] = groups[f.owner] || []).push(f);
    const owners = Object.keys(groups).sort((a, b) =>
      (b === state.user.username) - (a === state.user.username) || a.localeCompare(b));
    return owners.map((owner) => `
      <div class="category-header"><h3>${esc(owner)}${owner === state.user.username ? ` <small class="muted">(${esc(t('common.you'))})</small>` : ''}</h3></div>
      <div class="tiles">${groups[owner].map((f) => {
        const acc = myAccess(f);
        const cls = acc === 'none' ? 'locked' : acc === 'pending' ? 'pending' : 'ok';
        const flag = acc === 'public' ? 'globe' : acc === 'none' ? 'lock' : acc === 'pending' ? 'clock' : 'check';
        return `<button type="button" class="tile ${cls}" data-action="file" data-id="${f.id}">
          <span class="tile-flag">${icon(flag, 14)}</span>
          <span class="tile-name">${esc(f.name)}</span>
          <span class="tile-value">${esc(fmtBytes(f.size))}</span>
          <span class="tile-sub">${esc(t('files.access.' + acc))}</span>
        </button>`;
      }).join('')}</div>`).join('');
  }

  function renderUploadForm() {
    const others = state.users.filter((u) => u.username !== state.user.username && u.status === 'active');
    const isAdmin = state.user.role === 'admin';
    const pf = state.pendingFile;
    return `
      <div class="card upload-card">
        <div class="card-header">${icon('up')} ${esc(t('files.upload'))}</div>
        <div class="card-body">
          <form id="formUpload">
            <label class="drop ${pf ? 'has' : ''}" id="drop">
              <input type="file" id="fileInput" hidden>
              ${icon('up', 26)}
              <span id="dropText">${pf ? `<b>${esc(pf.name)}</b> · ${esc(fmtBytes(pf.size))}` : esc(t('files.drop'))}</span>
            </label>
            <label class="check">
              <input type="checkbox" id="protected" ${state.info.defaultProtected === false ? '' : 'checked'}>
              <span>${esc(t('files.protected'))}<small>${esc(t('files.protected.hint'))}</small></span>
            </label>
            <div class="form-grid" id="policyBox">
              <div>
                <label class="form-label">${esc(t('files.approvers'))}</label>
                <div class="chips" id="approvers">
                  ${others.length ? others.map((u) => `<label class="chip"><input type="checkbox" value="${esc(u.username)}"><span>${esc(u.username)}</span></label>`).join('') : '<span class="muted">—</span>'}
                </div>
                <small class="form-text">${esc(t('files.approvers.hint'))}</small>
              </div>
              <div>
                <label class="form-label">${esc(t('files.threshold'))}</label>
                <input class="form-control" type="number" id="threshold" min="1" value="1">
              </div>
            </div>
            <div class="form-grid">
              <div>
                <label class="form-label">${esc(t('files.visibility'))}</label>
                <select class="form-control" id="visibility"><option value="listed">${esc(t('files.vis.listed'))}</option><option value="hidden">${esc(t('files.vis.hidden'))}</option></select>
              </div>
              <div>
                ${isAdmin ? `<label class="form-label">&nbsp;</label><div class="alert success slim">${esc(t('files.adminUpload'))}</div>`
                  : `<label class="form-label">${esc(t('files.uploadKey'))}</label>
                     <input id="uploadKey" class="form-control mono" placeholder="XXXX-XXXX-XXXX-XXXX" value="${esc(state.prefillUploadKey)}">
                     <small class="form-text">${esc(t('files.uploadKey.hint'))}</small>`}
              </div>
            </div>
            <div class="row-btns">
              <button class="btn btn-primary" type="submit" id="btnUpload">${esc(t('files.btn.upload'))}</button>
              <div class="progress hidden" id="progress"><div class="bar"></div></div>
              <span class="muted small" id="upStatus"></span>
            </div>
          </form>
        </div>
      </div>`;
  }

  function renderFiles() {
    const open = state.showUpload || !state.files.length || !!state.prefillUploadKey;
    return `
      <div class="toolbar">
        <button type="button" class="btn btn-dark" data-action="toggle-upload">${icon('up')} ${esc(t('files.upload'))}</button>
        <div class="legend">
          <span><i class="sw ok"></i>${esc(t('legend.ok'))}</span>
          <span><i class="sw pending"></i>${esc(t('legend.pending'))}</span>
          <span><i class="sw locked"></i>${esc(t('legend.locked'))}</span>
        </div>
        <button type="button" class="btn btn-outline-secondary btn-sm" data-action="refresh">${esc(t('common.refresh'))}</button>
      </div>
      ${open ? renderUploadForm() : ''}
      <div id="fileTiles">${renderFileTiles()}</div>`;
  }

  async function hashFile(file, onProgress) {
    const h = LFS.sha256.create();
    const CHUNK = 4 * 1024 * 1024;
    for (let off = 0; off < file.size; off += CHUNK) {
      h.update(new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer()));
      onProgress(Math.min(100, Math.round(((off + CHUNK) / file.size) * 100)));
    }
    return h.hex();
  }

  async function doUpload(btn) {
    const file = state.pendingFile;
    if (!file) return toast(t('files.noFile'), 'err');
    const needsKey = $('#protected').checked;
    const approvers = needsKey ? $$('#approvers input:checked').map((i) => i.value) : [];
    const threshold = needsKey ? Number($('#threshold').value) || 1 : 1;
    const keyInput = $('#uploadKey');
    let grantId = null;
    if (keyInput && keyInput.value.trim()) {
      grantId = LFS.normalizeCode(keyInput.value);
      if (!grantId) return toast(t('err.bad_code'), 'err');
    }
    const status = $('#upStatus');
    const progress = $('#progress');
    const bar = $('.bar', progress);
    progress.classList.remove('hidden');

    await busy(btn, async () => {
      const sha256 = await hashFile(file, (pct) => {
        status.textContent = t('files.hashing', { pct });
        bar.style.width = pct + '%';
      });
      const meta = {
        name: file.name, size: file.size, sha256, mime: file.type || 'application/octet-stream',
        grantId, approvers, threshold, visibility: $('#visibility').value, protected: needsKey,
        uploader: state.user.username, ...fresh(),
      };
      const signature = LFS.sign(state.sk, 'upload', meta);
      const metaB64 = LFS.toB64(LFS.enc.encode(JSON.stringify(meta)));

      const result = await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('PUT', '/api/files');
        xhr.setRequestHeader('Authorization', 'Bearer ' + state.token);
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
        xhr.setRequestHeader('X-LFS-Meta', metaB64);
        xhr.setRequestHeader('X-LFS-Signature', signature);
        xhr.upload.onprogress = (e) => {
          if (!e.lengthComputable) return;
          const pct = Math.round((e.loaded / e.total) * 100);
          status.textContent = t('files.uploading', { pct });
          bar.style.width = pct + '%';
        };
        xhr.onload = () => {
          let j = {};
          try { j = JSON.parse(xhr.responseText); } catch (_) { /* ignore */ }
          if (xhr.status >= 200 && xhr.status < 300) resolve(j);
          else reject(new ApiError(j.message || j.error || 'HTTP ' + xhr.status, j.error));
        };
        xhr.onerror = () => reject(new ApiError(t('err.network'), 'network'));
        xhr.send(file);
      });

      toast(t('files.uploaded', { name: result.file.name }));
      state.pendingFile = null;
      state.prefillUploadKey = '';
      state.showUpload = false;
      await loadAll();
      render();
    });
    if (progress.isConnected) {
      progress.classList.add('hidden');
      status.textContent = '';
    }
  }

  async function doDownload(fileId, grantId, btn) {
    const f = state.files.find((x) => x.id === fileId) || (await api('GET', '/api/files/' + fileId)).file;
    if (grantId === undefined) {
      grantId = null;
      if (!f.canDownloadDirectly) {
        grantId = f.myGrants[0]?.id || null;
        if (!grantId) {
          toast(t('files.needKey'), 'err');
          return;
        }
      }
    }
    await busy(btn, async () => {
      const req = { fileId, grantId, username: state.user.username, ...fresh() };
      const r = await api('POST', `/api/files/${fileId}/download-token`, { ...req, signature: LFS.sign(state.sk, 'download', req) });
      triggerDownload(r.url, f.name);
      toast(t('files.downloading', { name: f.name }));
      setTimeout(refresh, 800);
    });
  }

  async function doDelete(fileId, btn) {
    const f = state.files.find((x) => x.id === fileId);
    if (!f || !confirm(t('files.delete.confirm', { name: f.name }))) return;
    await busy(btn, async () => {
      const obj = { fileId, by: state.user.username, ...fresh() };
      await api('POST', `/api/files/${fileId}/delete`, { nonce: obj.nonce, ts: obj.ts, signature: LFS.sign(state.sk, 'file-delete', obj) });
      closeModal();
      await loadAll();
      render();
    });
  }

  async function setAccess(fileId, needsKey, btn) {
    await busy(btn, async () => {
      const obj = { fileId, protected: needsKey, by: state.user.username, ...fresh() };
      await api('POST', `/api/files/${fileId}/access`,
        { protected: needsKey, nonce: obj.nonce, ts: obj.ts, signature: LFS.sign(state.sk, 'file-access', obj) });
      toast(needsKey ? t('files.nowProtected') : t('files.nowPublic'));
      await loadAll();
      renderDynamic();
      renderFileModal();
    });
  }

  // CTFd-style "challenge" modal: tabs, centered title, key box like a flag box.
  function renderFileModal() {
    const f = state.files.find((x) => x.id === state.modalFileId);
    if (!f) return closeModal();
    const acc = myAccess(f);
    const isOwner = f.owner === state.user.username;
    const canGet = f.canDownloadDirectly || acc === 'key';
    const sigOk = LFS.verify(f.ownerPublicKey, 'upload', f.uploadMeta, f.uploadSignature)
      && f.uploadMeta.sha256 === f.sha256 && f.uploadMeta.size === f.size;
    const tab = state.modalTab;
    const pending = f.myGrants.find((g) => g.status.startsWith('awaiting'));

    const fileTab = `
      <h2 class="modal-title-center">${esc(f.name)}</h2>
      <h4 class="modal-value">${esc(fmtBytes(f.size))}</h4>
      <div class="modal-tags">
        <span class="badge ${f.protected ? 'dark' : 'success'}">${icon(f.protected ? 'lock' : 'globe', 12)} ${esc(f.protected ? t('files.tag.protected') : t('files.tag.public'))}</span>
        ${f.protected ? `<span class="badge secondary">${esc(t('files.policy', { m: f.policy.threshold, n: f.policy.approvers.length }))}</span>` : ''}
        <span class="badge secondary">${esc(f.owner)}</span>
      </div>
      <p class="modal-desc">${esc(t('files.access.' + acc))}${pending ? ` — ${esc(t('status.' + pending.status))} (${esc(pending.id)})` : ''}</p>
      ${canGet ? `<div class="center-btns"><button type="button" class="btn btn-success btn-lg" data-action="download" data-id="${f.id}">${icon('down')} ${esc(t('files.btn.download'))}</button></div>` : ''}
      ${f.publicUrl ? `<div class="link-box"><code>${esc(location.origin + f.publicUrl)}</code><button type="button" class="btn btn-sm btn-outline-secondary" data-action="copy-code" data-code="${esc(location.origin + f.publicUrl)}">${esc(t('keys.copy'))}</button></div>` : ''}
      ${!canGet ? `
        <form id="formKeyInModal" class="flag-form">
          <input class="form-control mono" name="code" placeholder="${esc(t('files.keyPlaceholder'))}" autocomplete="off" spellcheck="false" ${pending ? `value="${esc(pending.id)}"` : ''}>
          <button class="btn btn-outline-secondary" type="submit">${esc(t('files.keySubmit'))}</button>
        </form>
        <div id="keyResult"></div>` : ''}
      ${f.canShare || isOwner || state.user.role === 'admin' ? `
        <hr>
        <div class="center-btns">
          ${f.canShare && f.protected ? `<button type="button" class="btn btn-primary btn-sm" data-action="share" data-id="${f.id}">${esc(t('files.btn.share'))}</button>` : ''}
          ${isOwner ? (f.protected
            ? `<button type="button" class="btn btn-outline-secondary btn-sm" data-action="access" data-id="${f.id}" data-value="public">${icon('globe', 14)} ${esc(t('files.makePublic'))}</button>`
            : `<button type="button" class="btn btn-outline-secondary btn-sm" data-action="access" data-id="${f.id}" data-value="protected">${icon('lock', 14)} ${esc(t('files.makeProtected'))}</button>`) : ''}
          ${isOwner || state.user.role === 'admin' ? `<button type="button" class="btn btn-outline-danger btn-sm" data-action="delete" data-id="${f.id}">${esc(t('files.btn.delete'))}</button>` : ''}
        </div>` : ''}`;

    const detailTab = `
      <table class="table kv-table">
        <tr><th>${esc(t('detail.uploader'))}</th><td><b>${esc(f.owner)}</b><br><code class="small">${esc(LFS.fingerprint(f.ownerPublicKey))}</code></td></tr>
        <tr><th>${esc(t('detail.uploadedAt'))}</th><td>${esc(fmtDate(f.uploadedAt))}</td></tr>
        <tr><th>${esc(t('detail.sha'))}</th><td><code class="wrap small">${esc(f.sha256)}</code></td></tr>
        <tr><th>${esc(t('detail.sig'))}</th><td>${sigOk
          ? `<span class="text-success">✔ ${esc(t('detail.sig.ok', { owner: f.owner }))}</span>`
          : `<span class="text-danger">✖ ${esc(t('detail.sig.bad'))}</span>`}</td></tr>
        <tr><th>${esc(t('detail.approvers'))}</th><td>${esc(f.policy.approvers.join(', '))} (${esc(t('files.policy', { m: f.policy.threshold, n: f.policy.approvers.length }))})</td></tr>
      </table>
      <h5>${esc(t('detail.verify'))}</h5>
      <p class="muted small">${esc(t('detail.verify.hint'))}</p>
      <input class="form-control" type="file" id="verifyInput" data-sha="${esc(f.sha256)}">
      <p id="verifyResult" class="small"></p>`;

    openModal(`
      <div class="modal-header">
        <ul class="nav-tabs">
          <li><button type="button" class="${tab === 'file' ? 'active' : ''}" data-mtab="file">${esc(t('modal.file'))}</button></li>
          <li><button type="button" class="${tab === 'detail' ? 'active' : ''}" data-mtab="detail">${esc(t('modal.detail'))}</button></li>
        </ul>
        <button type="button" class="close" data-close aria-label="${esc(t('common.close'))}">×</button>
      </div>
      <div class="modal-body">${tab === 'file' ? fileTab : detailTab}</div>`);
  }

  // Key typed into the file modal: verify it, sign as recipient, download if active.
  async function submitKeyInModal(form, btn) {
    const out = $('#keyResult');
    const code = LFS.normalizeCode(form.code.value);
    if (!code) {
      out.innerHTML = `<div class="alert danger">${esc(t('err.bad_code'))}</div>`;
      return;
    }
    await busy(btn, async () => {
      let g = (await api('GET', '/api/grants/' + code)).grant;
      if (g.payload.fileId !== state.modalFileId) {
        out.innerHTML = `<div class="alert danger">${esc(t('files.keyWrongFile'))}</div>`;
        return;
      }
      const v = verifyGrant(g);
      if (v.approvers.some((a) => a.valid === false) || !v.hashOk) {
        out.innerHTML = `<div class="alert danger">${esc(t('grant.invalidSig'))}</div>`;
        return;
      }
      if (g.me.canAccept) {
        const obj = { grantId: g.id, payloadHash: LFS.hashObject(g.payload), grantee: state.user.username };
        g = (await api('POST', `/api/grants/${g.id}/accept`, { signature: LFS.sign(state.sk, 'grant-accept', obj) })).grant;
      }
      await loadAll();
      renderDynamic();
      if (g.status === 'active') {
        out.innerHTML = `<div class="alert success">${esc(t('files.keyOk'))}</div>`;
        state.busy = false;
        await doDownload(g.payload.fileId, g.id, null);
        renderFileModal();
      } else {
        const signed = g.approvers.filter((a) => a.signature).length;
        out.innerHTML = `<div class="alert warning">${esc(t('status.' + g.status))} — ${signed}/${g.threshold} · ${esc(t('files.keyWait'))}</div>`;
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Keys
  // ---------------------------------------------------------------------------
  function verifyGrant(g) {
    const approvers = g.approvers.map((a) => ({
      ...a, valid: a.signature ? LFS.verify(a.publicKey, 'grant', g.payload, a.signature) : null,
    }));
    let acc = null;
    if (g.acceptance) {
      acc = LFS.verify(g.acceptance.publicKey, 'grant-accept',
        { grantId: g.id, payloadHash: LFS.hashObject(g.payload), grantee: g.acceptance.username }, g.acceptance.signature);
    }
    // The hash shown by the server must match what we compute ourselves.
    return { approvers, acc, hashOk: LFS.hashObject(g.payload) === g.payloadHash };
  }

  function targetText(g) {
    return g.payload.action === 'download'
      ? (g.file ? g.file.name : '—')
      : t('grant.perFile', { size: fmtBytes(g.payload.maxBytes) });
  }

  function renderGrantDetail() {
    const g = state.openGrant;
    if (!g) return '';
    const v = verifyGrant(g);
    const p = g.payload;
    const signed = v.approvers.filter((a) => a.valid).length;
    const anyInvalid = v.approvers.some((a) => a.valid === false) || v.acc === false || !v.hashOk;
    const steps = [
      [t('grant.flow.issue'), true],
      [t('grant.flow.cosign', { k: signed, m: g.threshold }), signed >= g.threshold],
      [t('grant.flow.accept'), !!g.acceptance && v.acc],
      [t('grant.flow.ready'), g.status === 'active'],
    ];
    const me = g.me;
    const canUseDownload = g.status === 'active' && p.action === 'download' && g.grantee === state.user.username;
    const canUseUpload = g.status === 'active' && p.action === 'upload' && g.grantee === state.user.username;
    return `
      <div class="grant card">
        <div class="card-header grant-head">
          <span class="code big">${esc(g.id)}</span>
          <span class="muted">${esc(t('keys.action.' + p.action))} · ${esc(targetText(g))}</span>
          ${statusBadge(g.status)}
        </div>
        <div class="card-body">
          <ol class="flow">${steps.map(([label, done], i) => `<li class="${done ? 'done' : ''}"><span class="dot">${done ? '✔' : i + 1}</span><span>${esc(label)}</span></li>`).join('')}</ol>
          <div class="form-grid">
            <table class="table kv-table">
              <tr><th>${esc(t('grant.issuer'))}</th><td><b>${esc(p.issuedBy)}</b></td></tr>
              <tr><th>${esc(t('keys.col.grantee'))}</th><td><b>${esc(g.grantee === '*' ? t('keys.anyone') : g.grantee)}</b></td></tr>
              ${g.file ? `<tr><th>${esc(t('grant.file'))}</th><td>${esc(g.file.name)} · ${esc(fmtBytes(g.file.size))}</td></tr>` : ''}
              <tr><th>${esc(t('grant.uses'))}</th><td>${g.usesLeft}/${p.maxUses}</td></tr>
              <tr><th>${esc(t('grant.expires'))}</th><td>${esc(fmtDate(p.expiresAt))}</td></tr>
              ${p.note ? `<tr><th>${esc(t('grant.note'))}</th><td>${esc(p.note)}</td></tr>` : ''}
              <tr><th>${esc(t('grant.hash'))}</th><td><code class="small">${esc(g.payloadHash.slice(0, 32))}…</code></td></tr>
            </table>
            <div>
              <label class="form-label">${esc(t('grant.sigs'))}</label>
              <ul class="sigs">
                ${v.approvers.map((a) => `<li class="${a.valid === null ? 'wait' : a.valid ? 'ok' : 'bad'}">
                  <span class="sig-ico">${a.valid === null ? '…' : a.valid ? '✔' : '✖'}</span>
                  <span><b>${esc(a.username)}</b> <small class="muted">${esc(t('grant.role.approver'))}</small>
                  <code class="small block">${a.publicKey ? esc(LFS.fingerprint(a.publicKey)) : ''}</code></span>
                  <em>${esc(a.valid === null ? t('grant.sig.missing') : a.valid ? t('grant.sig.valid') : t('grant.sig.invalid'))}</em></li>`).join('')}
                <li class="${g.acceptance ? (v.acc ? 'ok' : 'bad') : 'wait'}">
                  <span class="sig-ico">${g.acceptance ? (v.acc ? '✔' : '✖') : '…'}</span>
                  <span><b>${esc(g.acceptance ? g.acceptance.username : (g.grantee === '*' ? t('keys.anyone') : g.grantee))}</b> <small class="muted">${esc(t('grant.role.recipient'))}</small></span>
                  <em>${esc(!g.acceptance ? t('grant.sig.missing') : v.acc ? t('grant.sig.valid') : t('grant.sig.invalid'))}</em></li>
              </ul>
            </div>
          </div>
          ${anyInvalid ? `<div class="alert danger">${esc(t('grant.invalidSig'))}</div>` : ''}
          <div class="row-btns">
            ${me.canAccept ? `<button type="button" class="btn btn-primary" data-action="accept" ${anyInvalid ? 'disabled' : ''}>${esc(t('grant.btn.accept'))}</button>` : ''}
            ${me.canApprove ? `<button type="button" class="btn btn-primary" data-action="approve" ${anyInvalid ? 'disabled' : ''}>${esc(t('grant.btn.approve'))}</button>` : ''}
            ${canUseDownload ? `<button type="button" class="btn btn-success" data-action="grant-download">${esc(t('grant.btn.download'))}</button>` : ''}
            ${canUseUpload ? `<button type="button" class="btn btn-success" data-action="grant-upload">${esc(t('grant.btn.useUpload'))}</button>` : ''}
            <button type="button" class="btn btn-outline-secondary" data-action="copy-code" data-code="${esc(g.id)}">${esc(t('keys.copy'))}</button>
            ${me.canRevoke ? `<button type="button" class="btn btn-outline-danger" data-action="revoke">${esc(t('grant.btn.revoke'))}</button>` : ''}
          </div>
        </div>
      </div>`;
  }

  function renderTodo() {
    const todo = state.grants.filter((g) => g.me.canApprove || g.me.canAccept);
    if (!todo.length) return `<p class="empty">${esc(t('keys.todo.empty'))}</p>`;
    return `<div class="list-group">${todo.map((g) => `
      <button type="button" class="list-item" data-action="open-grant" data-code="${esc(g.id)}">
        <span class="code">${esc(g.id)}</span>
        <span class="grow">${esc(t('keys.action.' + g.payload.action))} · ${esc(targetText(g))} · ${esc(g.payload.issuedBy)}</span>
        <span class="badge warning">${esc(g.me.canAccept ? t('grant.btn.accept') : t('grant.btn.approve'))}</span>
      </button>`).join('')}</div>`;
  }

  function renderGrantsTable() {
    if (!state.grants.length) return `<p class="empty">${esc(t('keys.all.empty'))}</p>`;
    return `<div class="table-wrap"><table class="table striped hover">
      <thead><tr><th>${esc(t('keys.col.code'))}</th><th>${esc(t('keys.col.action'))}</th><th>${esc(t('keys.col.target'))}</th>
        <th>${esc(t('keys.col.grantee'))}</th><th class="center">${esc(t('keys.col.sigs'))}</th><th>${esc(t('keys.col.status'))}</th></tr></thead>
      <tbody>${state.grants.map((g) => `
        <tr class="clickable" data-action="open-grant" data-code="${esc(g.id)}">
          <td><span class="code">${esc(g.id)}</span></td>
          <td>${esc(t('keys.action.' + g.payload.action))}</td>
          <td>${esc(targetText(g))}</td>
          <td>${esc(g.grantee === '*' ? t('keys.anyone') : g.grantee)}</td>
          <td class="center">${g.approvers.filter((a) => a.signature).length}/${g.threshold}${g.acceptance ? ' + ✔' : ''}</td>
          <td>${statusBadge(g.status)}</td>
        </tr>`).join('')}</tbody></table></div>`;
  }

  function renderCreated() {
    const g = state.createdGrant;
    if (!g) return '';
    const missing = g.approvers.filter((a) => !a.signature).map((a) => a.username);
    const need = g.threshold - (g.approvers.length - missing.length);
    return `
      <div class="alert success created">
        <div>${esc(t('keys.created'))}</div>
        <div class="created-code"><span class="code big">${esc(g.id)}</span>
          <button type="button" class="btn btn-sm btn-outline-secondary" data-action="copy-code" data-code="${esc(g.id)}">${esc(t('keys.copy'))}</button></div>
        ${need > 0 ? `<div class="small">${esc(t('keys.created.cosign', { k: need, who: missing.join(', ') }))}</div>` : ''}
      </div>`;
  }

  function renderKeys() {
    const isAdmin = state.user.role === 'admin';
    const shareable = state.files.filter((f) => f.canShare && f.protected);
    const others = state.users.filter((u) => u.username !== state.user.username && u.status === 'active');
    return `
      <div class="keys-grid">
        <div>
          <div class="card">
            <div class="card-header">${esc(t('keys.open'))}</div>
            <div class="card-body">
              <p class="muted small">${esc(t('keys.open.hint'))}</p>
              <form id="formOpenKey" class="flag-form">
                <input id="openCode" class="form-control mono" placeholder="XXXX-XXXX-XXXX-XXXX" autocomplete="off" spellcheck="false">
                <button class="btn btn-outline-secondary" type="submit">${esc(t('keys.btn.open'))}</button>
              </form>
            </div>
          </div>
          <div class="card">
            <div class="card-header">${esc(t('keys.todo'))}</div>
            <div class="card-body" id="keysTodo">${renderTodo()}</div>
          </div>
        </div>
        <div class="card">
          <div class="card-header">${esc(t('keys.create'))}</div>
          <div class="card-body">
            <form id="formCreateKey">
              <div class="form-grid">
                <div><label class="form-label">${esc(t('keys.type'))}</label>
                  <select class="form-control" name="action">
                    <option value="download">${esc(t('keys.type.download'))}</option>
                    ${isAdmin ? `<option value="upload">${esc(t('keys.type.upload'))}</option>` : ''}
                  </select></div>
                <div data-for="download"><label class="form-label">${esc(t('keys.file'))}</label>
                  ${shareable.length ? `<select class="form-control" name="fileId">${shareable.map((f) => `<option value="${f.id}" ${state.shareFileId === f.id ? 'selected' : ''}>${esc(f.name)} (${esc(t('files.policy', { m: f.policy.threshold, n: f.policy.approvers.length }))})</option>`).join('')}</select>`
                    : `<div class="muted small">${esc(t('keys.file.none'))}</div>`}</div>
                <div data-for="upload"><label class="form-label">${esc(t('keys.maxmb'))}</label>
                  <input class="form-control" type="number" name="maxmb" min="1" value="100"></div>
                <div><label class="form-label">${esc(t('keys.grantee'))}</label>
                  <select class="form-control" name="grantee">
                    ${others.map((u) => `<option value="${esc(u.username)}">${esc(u.username)}</option>`).join('')}
                    <option value="*">${esc(t('keys.grantee.any'))}</option>
                  </select></div>
                <div><label class="form-label">${esc(t('keys.uses'))}</label>
                  <input class="form-control" type="number" name="uses" min="1" max="1000" value="1"></div>
                <div><label class="form-label">${esc(t('keys.hours'))}</label>
                  <input class="form-control" type="number" name="hours" min="1" max="${state.info.maxGrantDays * 24}" value="24"></div>
              </div>
              <label class="form-label">${esc(t('keys.note'))}</label>
              <input class="form-control" name="note" maxlength="200">
              <div class="row-btns"><button class="btn btn-primary" type="submit">${esc(t('keys.btn.create'))}</button></div>
            </form>
            <div id="createdKey">${renderCreated()}</div>
          </div>
        </div>
      </div>
      <div id="grantDetail">${renderGrantDetail()}</div>
      <div class="section-head"><h3>${esc(t('keys.all'))}</h3>
        <button type="button" class="btn btn-outline-secondary btn-sm" data-action="refresh">${esc(t('common.refresh'))}</button></div>
      <div id="keysAll">${renderGrantsTable()}</div>`;
  }

  function syncCreateForm() {
    const form = $('#formCreateKey');
    if (!form) return;
    const action = form.action.value;
    $$('[data-for]', form).forEach((el) => el.classList.toggle('hidden', el.dataset.for !== action));
  }

  async function openGrant(code) {
    const id = LFS.normalizeCode(code);
    if (!id) return toast(t('err.bad_code'), 'err');
    try {
      state.openGrant = (await api('GET', '/api/grants/' + id)).grant;
      if (state.view !== 'keys') {
        state.view = 'keys';
        render();
      } else {
        $('#grantDetail').innerHTML = renderGrantDetail();
      }
      $('#grantDetail')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
      toastErr(e);
    }
  }

  async function createKey(form, btn) {
    const action = form.action.value;
    const fileId = action === 'download' ? form.fileId?.value : null;
    if (action === 'download' && !fileId) return toast(t('keys.file.none'), 'err');
    await busy(btn, async () => {
      const f = fileId ? state.files.find((x) => x.id === fileId) : null;
      const payload = {
        id: LFS.newCode(), action, fileId: fileId || null, fileSha256: f ? f.sha256 : null,
        grantee: form.grantee.value,
        maxUses: Number(form.uses.value) || 1,
        maxBytes: action === 'upload' ? Math.round(Number(form.maxmb.value) * 1024 * 1024) : null,
        expiresAt: Date.now() + Number(form.hours.value) * 3600_000,
        issuedBy: state.user.username, issuedAt: Date.now(), nonce: LFS.randomHex(16),
      };
      if (form.note.value.trim()) payload.note = form.note.value.trim();
      const r = await api('POST', '/api/grants', { payload, signature: LFS.sign(state.sk, 'grant', payload) });
      state.createdGrant = r.grant;
      state.openGrant = r.grant;
      await loadAll();
      $('#createdKey').innerHTML = renderCreated();
      renderDynamic();
    });
  }

  async function grantAction(kind, btn) {
    const g = state.openGrant;
    if (!g) return;
    if (kind === 'revoke' && !confirm(t('grant.revoke.confirm', { code: g.id }))) return;
    await busy(btn, async () => {
      let r;
      if (kind === 'accept') {
        const obj = { grantId: g.id, payloadHash: LFS.hashObject(g.payload), grantee: state.user.username };
        r = await api('POST', `/api/grants/${g.id}/accept`, { signature: LFS.sign(state.sk, 'grant-accept', obj) });
        toast(t('grant.accepted'));
      } else if (kind === 'approve') {
        r = await api('POST', `/api/grants/${g.id}/approve`, { signature: LFS.sign(state.sk, 'grant', g.payload) });
        toast(t('grant.approved'));
      } else {
        const obj = { grantId: g.id, by: state.user.username, ...fresh() };
        r = await api('POST', `/api/grants/${g.id}/revoke`, { nonce: obj.nonce, ts: obj.ts, signature: LFS.sign(state.sk, 'grant-revoke', obj) });
        toast(t('grant.revoked'));
      }
      state.openGrant = r.grant;
      await loadAll();
      renderDynamic();
    });
  }

  // ---------------------------------------------------------------------------
  // Identity & admin
  // ---------------------------------------------------------------------------
  function renderIdentity() {
    const id = state.identity;
    return `
      <div class="keys-grid">
        <div class="card">
          <div class="card-header">${esc(t('id.title'))}</div>
          <div class="card-body">
            <table class="table kv-table">
              <tr><th>${esc(t('id.username'))}</th><td><b>${esc(id.username)}</b></td></tr>
              <tr><th>${esc(t('id.role'))}</th><td>${esc(t('role.' + state.user.role))}</td></tr>
              <tr><th>${esc(t('id.fp'))}</th><td><code>${esc(LFS.fingerprint(id.publicKey))}</code></td></tr>
              <tr><th>${esc(t('id.pub'))}</th><td><code class="wrap small">${esc(id.publicKey)}</code></td></tr>
            </table>
            <div class="row-btns">
              <button type="button" class="btn btn-primary" data-action="export">${esc(t('id.export'))}</button>
              <button type="button" class="btn btn-outline-danger" data-action="forget">${esc(t('id.forget'))}</button>
            </div>
            <small class="form-text">${esc(t('id.export.hint'))}</small>
          </div>
        </div>
        <div class="card">
          <div class="card-header">${esc(t('id.server'))}</div>
          <div class="card-body">
            <table class="table kv-table">
              <tr><th>${esc(t('auth.fp'))}</th><td><code>${esc(state.info.fingerprint)}</code></td></tr>
              <tr><th>URL</th><td><code>${esc(location.origin)}</code></td></tr>
            </table>
            <h5>${esc(t('id.modes'))}</h5>
            <ul class="modes">
              <li><b>1</b><span>${esc(t('id.mode1'))}</span></li>
              <li><b>2</b><span>${esc(t('id.mode2'))}</span></li>
              <li><b>N</b><span>${esc(t('id.modeN'))}</span></li>
            </ul>
          </div>
        </div>
      </div>`;
  }

  function renderUsersTable() {
    return `<div class="table-wrap"><table class="table striped">
      <thead><tr><th>${esc(t('admin.col.user'))}</th><th>${esc(t('id.fp'))}</th><th>${esc(t('admin.col.role'))}</th><th>${esc(t('admin.col.status'))}</th><th></th></tr></thead>
      <tbody>${state.users.map((u) => `
        <tr><td><b>${esc(u.username)}</b>${u.username === state.user.username ? ` <small class="muted">(${esc(t('common.you'))})</small>` : ''}</td>
          <td><code class="small">${esc(u.fingerprint)}</code></td>
          <td>${u.role === 'admin' ? '<span class="badge dark">admin</span>' : esc(t('role.user'))}</td>
          <td><span class="badge ${u.status === 'active' ? 'success' : u.status === 'pending' ? 'warning' : 'secondary'}">${esc(t('ustatus.' + u.status))}</span></td>
          <td class="actions">
            ${u.status !== 'active' ? `<button type="button" class="btn btn-sm btn-success" data-action="admin" data-user="${esc(u.username)}" data-field="status" data-value="active">${esc(t('admin.activate'))}</button>`
              : `<button type="button" class="btn btn-sm btn-outline-secondary" data-action="admin" data-user="${esc(u.username)}" data-field="status" data-value="disabled">${esc(t('admin.disable'))}</button>`}
            ${u.role === 'admin' ? `<button type="button" class="btn btn-sm btn-outline-secondary" data-action="admin" data-user="${esc(u.username)}" data-field="role" data-value="user">${esc(t('admin.makeUser'))}</button>`
              : `<button type="button" class="btn btn-sm btn-outline-secondary" data-action="admin" data-user="${esc(u.username)}" data-field="role" data-value="admin">${esc(t('admin.makeAdmin'))}</button>`}
          </td></tr>`).join('')}</tbody></table></div>`;
  }

  function renderAuditTable() {
    if (!state.audit.length) return `<p class="empty">—</p>`;
    return `<div class="table-wrap audit"><table class="table striped small">
      <thead><tr><th>${esc(t('admin.col.time'))}</th><th>${esc(t('admin.col.user'))}</th><th>${esc(t('admin.col.action'))}</th><th>${esc(t('admin.col.detail'))}</th><th>IP</th></tr></thead>
      <tbody>${state.audit.map((e) => `
        <tr><td class="nowrap">${esc(fmtDate(e.ts))}</td><td>${esc(e.actor)}</td><td><code>${esc(e.action)}</code></td>
          <td class="small">${esc(e.detail ? JSON.stringify(e.detail) : '')}</td><td class="small nowrap">${esc(e.ip || '')}</td></tr>`).join('')}</tbody></table></div>`;
  }

  function renderAdmin() {
    return `
      <div class="section-head"><h3>${esc(t('admin.users'))}</h3>
        <button type="button" class="btn btn-outline-secondary btn-sm" data-action="refresh">${esc(t('common.refresh'))}</button></div>
      <div id="adminUsers">${renderUsersTable()}</div>
      <div class="section-head"><h3>${esc(t('admin.audit'))}</h3></div>
      <p class="muted small">${esc(t('admin.audit.hint'))}</p>
      <div id="adminAudit">${renderAuditTable()}</div>`;
  }

  async function adminUpdate(btn) {
    const { user, field, value } = btn.dataset;
    await busy(btn, async () => {
      const obj = { username: user, [field]: value, by: state.user.username, ...fresh() };
      await api('POST', '/api/admin/users/' + encodeURIComponent(user),
        { [field]: value, nonce: obj.nonce, ts: obj.ts, signature: LFS.sign(state.sk, 'admin-user', obj) });
      toast(t('admin.updated', { user }));
      await loadAll();
      renderDynamic();
    });
  }

  function exportIdentity() {
    const blob = new Blob([JSON.stringify(state.identity, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    triggerDownload(url, `${state.identity.username}.lfs-identity.json`);
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  // ---------------------------------------------------------------------------
  // Events (delegated; CSP forbids inline handlers)
  // ---------------------------------------------------------------------------
  document.addEventListener('click', async (e) => {
    const langBtn = e.target.closest('[data-lang]');
    if (langBtn) {
      state.lang = langBtn.dataset.lang;
      ls.set('lfs.lang', state.lang);
      render();
      return;
    }
    if (e.target.closest('[data-close]') || e.target.id === 'modal') return closeModal();

    const mtab = e.target.closest('[data-mtab]');
    if (mtab) {
      state.modalTab = mtab.dataset.mtab;
      renderFileModal();
      return;
    }
    const tab = e.target.closest('[data-authtab]');
    if (tab) {
      state.authTab = tab.dataset.authtab;
      render();
      return;
    }
    const nav = e.target.closest('[data-view]');
    if (nav) {
      state.view = nav.dataset.view;
      state.navOpen = false;
      if (state.view !== 'keys') state.createdGrant = null;
      if (state.view === 'public') await loadPublic();
      else if (state.user) await loadAll().catch(() => {});
      render();
      window.scrollTo(0, 0);
      return;
    }

    const el = e.target.closest('[data-action]');
    if (!el) return;
    const { action, id } = el.dataset;
    switch (action) {
      case 'logout': await logout(); break;
      case 'toggle-nav': state.navOpen = !state.navOpen; renderNavbar(); break;
      case 'toggle-upload': state.showUpload = !state.showUpload; render(); break;
      case 'refresh': await busy(el, async () => { await loadAll(); renderDynamic(); }); break;
      case 'file':
        state.modalFileId = id;
        state.modalTab = 'file';
        renderFileModal();
        break;
      case 'download': await doDownload(id, undefined, el); break;
      case 'delete': await doDelete(id, el); break;
      case 'access': await setAccess(id, el.dataset.value === 'protected', el); break;
      case 'share':
        closeModal();
        state.shareFileId = id;
        state.createdGrant = null;
        state.view = 'keys';
        await loadAll().catch(() => {});
        render();
        $('#formCreateKey')?.scrollIntoView({ behavior: 'smooth' });
        break;
      case 'open-grant': await openGrant(el.dataset.code); break;
      case 'copy-code': await copy(el.dataset.code, el); break;
      case 'accept': case 'approve': case 'revoke': await grantAction(action, el); break;
      case 'grant-download': await doDownload(state.openGrant.payload.fileId, state.openGrant.id, el); break;
      case 'grant-upload':
        state.prefillUploadKey = state.openGrant.id;
        state.view = 'files';
        render();
        break;
      case 'admin': await adminUpdate(el); break;
      case 'export': exportIdentity(); break;
      case 'forget':
        if (confirm(t('id.forget.confirm'))) {
          ls.del('lfs.identity');
          state.identity = null;
          if (state.user) await logout();
          state.authTab = 'create';
          state.view = 'login';
          render();
        }
        break;
      case 'repin':
        pin(state.info.serverPublicKey);
        render();
        break;
      default:
    }
  });

  document.addEventListener('change', async (e) => {
    if (e.target.id === 'mutual') {
      state.mutual = e.target.checked;
      ls.set('lfs.mutual', state.mutual);
    } else if (e.target.id === 'fileInput') {
      setPendingFile(e.target.files[0]);
    } else if (e.target.id === 'protected') {
      $('#policyBox')?.classList.toggle('disabled', !e.target.checked);
    } else if (e.target.closest('#formCreateKey') && e.target.name === 'action') {
      syncCreateForm();
    } else if (e.target.id === 'verifyInput') {
      const file = e.target.files[0];
      const out = $('#verifyResult');
      if (!file) return;
      const digest = await hashFile(file, (pct) => { out.textContent = t('files.hashing', { pct }); });
      const okMatch = digest === e.target.dataset.sha;
      out.className = 'small ' + (okMatch ? 'text-success' : 'text-danger');
      out.textContent = (okMatch ? t('detail.verify.ok') : t('detail.verify.bad')) + ' — ' + digest;
    }
  });

  function setPendingFile(file) {
    if (!file) return;
    state.pendingFile = file;
    const drop = $('#drop');
    if (drop) {
      drop.classList.add('has');
      $('#dropText').innerHTML = `<b>${esc(file.name)}</b> · ${esc(fmtBytes(file.size))}`;
    }
  }

  document.addEventListener('dragover', (e) => {
    const drop = e.target.closest && e.target.closest('#drop');
    if (drop) { e.preventDefault(); drop.classList.add('over'); }
  });
  document.addEventListener('dragleave', (e) => {
    const drop = e.target.closest && e.target.closest('#drop');
    if (drop) drop.classList.remove('over');
  });
  document.addEventListener('drop', (e) => {
    const drop = e.target.closest && e.target.closest('#drop');
    if (!drop) return;
    e.preventDefault();
    drop.classList.remove('over');
    setPendingFile(e.dataTransfer.files[0]);
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('#modal').classList.contains('hidden')) closeModal();
  });

  document.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const btn = e.submitter || $('button[type=submit]', form);

    if (form.id === 'formLogin') {
      const mode = btn.dataset.mode;
      state.authLog = [];
      await busy(btn, async () => {
        unlock(form.pass.value);
        if (mode === 'register') {
          const u = await register();
          if (u.status !== 'active') {
            toast(t('auth.pending'));
            return;
          }
        }
        await login();
      });
    } else if (form.id === 'formCreate') {
      const username = form.username.value.trim().toLowerCase();
      if (form.pass.value !== form.pass2.value) return toast(t('err.mismatch'), 'err');
      if (form.pass.value.length < 8) return toast(t('err.passphrase_short'), 'err');
      state.authLog = [];
      await busy(btn, async () => {
        const { file, secretKey } = LFS.createIdentityFile(username, form.pass.value);
        // Register first so a taken username does not leave an orphan identity behind.
        state.identity = file;
        state.sk = secretKey;
        try {
          const u = await register();
          ls.set('lfs.identity', file);
          if (u.status !== 'active') {
            toast(t('auth.pending'));
            render();
            return;
          }
        } catch (err) {
          state.identity = ls.get('lfs.identity', null);
          state.sk = null;
          throw err;
        }
        await login();
      });
    } else if (form.id === 'formImport') {
      const file = form.file.files[0];
      state.authLog = [];
      await busy(btn, async () => {
        let parsed;
        try {
          parsed = JSON.parse(await file.text());
          if (parsed.type !== 'lfs-identity') throw new Error();
        } catch (_) {
          throw new ApiError(t('err.bad_file'), 'bad_file');
        }
        state.identity = parsed;
        try {
          unlock(form.pass.value);
        } catch (err) {
          state.identity = ls.get('lfs.identity', null);
          throw err;
        }
        ls.set('lfs.identity', parsed);
        await login();
      });
    } else if (form.id === 'formUpload') {
      await doUpload(btn);
    } else if (form.id === 'formOpenKey') {
      await openGrant($('#openCode').value);
    } else if (form.id === 'formCreateKey') {
      await createKey(form, btn);
    } else if (form.id === 'formKeyInModal') {
      await submitKeyInModal(form, btn);
    }
  });

  // ---------------------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------------------
  async function boot() {
    renderNavbar();
    try {
      state.info = await api('GET', '/api/info');
    } catch (e) {
      $('#root').innerHTML = `<div class="container center"><div class="alert danger">${esc(errText(e))}</div></div>`;
      return;
    }
    await loadPublic();
    // Nothing public to show → go straight to the login page.
    state.view = state.publicFiles.length ? 'public' : 'login';
    render();
    setInterval(() => { if (!document.hidden && !state.busy) refresh(); }, 8000);
  }
  boot();
})();
