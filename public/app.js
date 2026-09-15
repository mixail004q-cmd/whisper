// ============================================================
//  WHISPER — клиент (полная версия v2)
// ============================================================

const API = '/api';

let state = {
  user: null,
  filter: 'all',
  editingPostId: null,
  editingType: 'secret',
  currentPostId: null,
  editingCommentId: null,
  supportPollTimer: null,
  notifyPollTimer: null,
  currentTicketId: null
};

// ============ API helper ============
async function api(path, options = {}) {
  const opts = {
    method: options.method || 'GET',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...options
  };
  if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
  const r = await fetch(API + path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || 'Ошибка');
  return data;
}

// ============ Utils ============
const $ = id => document.getElementById(id);

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));

const firstLetter = n => n ? String(n).trim().charAt(0).toUpperCase() : '?';

function fmt(iso) {
  const d = new Date(iso);
  const now = new Date();
  const diff = (now - d) / 1000;
  if (diff < 60) return 'только что';
  if (diff < 3600) return Math.floor(diff / 60) + ' мин назад';
  if (diff < 86400) return Math.floor(diff / 3600) + ' ч назад';
  const pad = n => String(n).padStart(2, '0');
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const ROLE_LABEL = {
  main_admin: 'главный админ',
  admin: 'админ',
  support: 'поддержка',
  user: ''
};

const ROLE_SHORT = ROLE_LABEL;

// ============ ROUTER ============
const App = {
  go(view, params) {
    ['feed', 'post', 'profile', 'staff', 'mod'].forEach(v => {
      const el = $(v + 'View');
      if (el) el.classList.add('hidden');
    });
    document.querySelectorAll('.nav-tabs button').forEach(b => b.classList.remove('active'));

    if (view === 'feed') {
      $('feedView').classList.remove('hidden');
      $('navFeed').classList.add('active');
      loadFeed();
    }
    if (view === 'post') {
      $('postView').classList.remove('hidden');
      loadPost(params);
    }
    if (view === 'profile') {
      $('profileView').classList.remove('hidden');
      $('navProfile').classList.add('active');
      loadProfile();
    }
    if (view === 'staff') {
      $('staffView').classList.remove('hidden');
      $('navStaff').classList.add('active');
      loadStaff();
    }
    if (view === 'mod') {
      $('modView').classList.remove('hidden');
      $('navMod').classList.add('active');
      loadModeration();
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
};
window.App = App;

// ============ AUTH ============
let authMode = 'login';

function setAuthMode(m) {
  authMode = m;
  $('tabLogin').classList.toggle('active', m === 'login');
  $('tabRegister').classList.toggle('active', m === 'register');
  $('authBtn').textContent = m === 'login' ? 'Войти' : 'Зарегистрироваться';
  $('pass2Input').style.display = m === 'register' ? 'block' : 'none';
  $('emailInput').style.display = m === 'register' ? 'block' : 'none';
  $('authError').textContent = '';
}

async function doAuth() {
  $('authError').textContent = '';
  const login = $('loginInput').value.trim();
  const password = $('passInput').value;

  try {
    if (authMode === 'register') {
      const password2 = $('pass2Input').value;
      const email = $('emailInput').value.trim();
      if (password !== password2) {
        $('authError').textContent = 'Пароли не совпадают';
        return;
      }
      if (password.length < 8) {
        $('authError').textContent = 'Пароль от 8 символов';
        return;
      }
      const body = { login, password };
      if (email) body.email = email;
      if (window.TURNSTILE_ENABLED && window.turnstile) {
        body.turnstileToken = window.turnstile.getResponse();
      }
      const d = await api('/register', { method: 'POST', body });
      state.user = d.user;
    } else {
      const d = await api('/login', { method: 'POST', body: { login, password } });
      state.user = d.user;
    }
    $('loginInput').value = '';
    $('passInput').value = '';
    $('pass2Input').value = '';
    $('emailInput').value = '';
    if (window.turnstile && window.TURNSTILE_ENABLED) window.turnstile.reset();
    renderAuth();
    App.go('feed');
  } catch (e) {
    $('authError').textContent = e.message;
  }
}

async function logout() {
  try { await api('/logout', { method: 'POST' }); } catch (e) {}
  state.user = null;
  stopPolling();
  renderAuth();
}

function renderAuth() {
  const loggedIn = !!state.user;
  $('authSection').classList.toggle('hidden', loggedIn);
  $('appSection').classList.toggle('hidden', !loggedIn);
  $('supportFab').classList.toggle('hidden', !loggedIn);
  $('navTabs').style.display = loggedIn ? 'flex' : 'none';
  renderNav();

  if (loggedIn) {
    const staffRoles = ['main_admin', 'admin', 'support'];
    const modRoles = ['main_admin', 'admin'];
    $('navStaff').classList.toggle('hidden', !staffRoles.includes(state.user.role));
    $('navMod').classList.toggle('hidden', !modRoles.includes(state.user.role));
    startPolling();
  } else {
    $('navStaff').classList.add('hidden');
    $('navMod').classList.add('hidden');
  }
}

function renderNav() {
  const el = $('navUser');
  if (!state.user) { el.innerHTML = ''; return; }

  const roleTag = state.user.role !== 'user'
    ? `<span class="role-tag ${state.user.role}">${esc(ROLE_SHORT[state.user.role])}</span>`
    : '';

  el.innerHTML = `
    <span class="user-name">${esc(state.user.login)}</span>
    ${roleTag}
    <button id="settingsBtn">⚙</button>
    <button id="logoutBtn">Выйти</button>`;

  $('logoutBtn').onclick = logout;
  $('settingsBtn').onclick = openSettings;
}

// ============ POSTS ============
async function loadFeed() {
  try {
    const q = state.filter === 'all' ? '' : '?type=' + state.filter;
    const d = await api('/posts' + q);
    $('feedCount').textContent = d.posts.length;

    if (d.posts.length === 0) {
      $('postsWrap').innerHTML = '';
      $('emptyState').classList.remove('hidden');
      return;
    }
    $('emptyState').classList.add('hidden');
    $('postsWrap').innerHTML = d.posts.map(renderPostCard).join('');

    document.querySelectorAll('.post').forEach(el => {
      el.onclick = () => App.go('post', parseInt(el.dataset.id, 10));
    });
  } catch (e) {
    console.error(e);
  }
}

function renderPostCard(p) {
  const typeLabel = p.type === 'secret' ? 'Секрет' : 'История';
  const authorClass = p.is_anon ? 'post-author anon' : 'post-author';
  const authorText = p.is_anon ? 'Аноним' : esc(p.author_name);
  const edited = p.edited_at ? ` · изменено ${fmt(p.edited_at)}` : '';
  const cnt = p.comments_count;
  const word = cnt == 1 ? 'комментарий' : (cnt > 1 && cnt < 5 ? 'комментария' : 'комментариев');

  return `<div class="post" data-id="${p.id}">
    <div class="post-head">
      <span class="post-type ${p.type}">${typeLabel}</span>
      <span class="${authorClass}">${authorText}</span>
      <span class="post-time">${fmt(p.created_at)}${edited}</span>
    </div>
    <div class="post-body">${esc(p.body)}</div>
    <div class="post-foot">
      <span>${cnt} ${word}</span>
      <span>Открыть →</span>
    </div>
  </div>`;
}

async function loadPost(id) {
  state.currentPostId = id;
  try {
    const d = await api('/posts/' + id);
    renderPostView(d.post, d.comments);
  } catch (e) {
    $('postView').innerHTML = `<div class="empty">${esc(e.message)}</div>`;
  }
}

function renderPostView(post, comments) {
  const typeLabel = post.type === 'secret' ? 'Секрет' : 'История';
  const authorClass = post.is_anon ? 'post-author anon' : 'post-author';
  const authorText = post.is_anon ? 'Аноним' : esc(post.author_name);
  const edited = post.edited_at ? ` · изменено ${fmt(post.edited_at)}` : '';

  const myId = state.user ? state.user.id : null;
  const myLogin = state.user ? state.user.login : null;
  const isOwner = post.user_id && myId && post.user_id === myId;
  const isStaff = state.user && ['main_admin', 'admin'].includes(state.user.role);
  const canPin = isOwner || isStaff;

  const sorted = (comments || []).slice().sort((a, b) => {
    if (a.pinned !== b.pinned) return b.pinned - a.pinned;
    return new Date(a.created_at) - new Date(b.created_at);
  });

  let commentsHtml = '';
  if (!post.allow_comments) {
    commentsHtml = '<div class="empty">Автор отключил комментарии</div>';
  } else {
    const list = sorted.length > 0
      ? sorted.map(c => renderComment(post, c, canPin)).join('')
      : '<div class="empty">Комментариев пока нет</div>';
    commentsHtml = `
      <div class="comments-title">Комментарии <span class="count-badge">${comments.length}</span></div>
      <div class="comments-list">${list}</div>
      <div class="comment-form-block">
        <textarea id="newCommentInput" placeholder="Написать комментарий..." maxlength="500"></textarea>
        <div class="form-footer">
          <span style="font-size:11px;color:var(--text-mute)" id="commentCounter">0 / 500</span>
          <button id="btnSendComment">Отправить</button>
        </div>
      </div>`;
  }

  let ownerBar = '';
  if (isOwner) {
    ownerBar = `<div class="post-owner-actions">
      <button id="btnEditOwn">Изменить</button>
      <button id="btnDeleteOwn">Удалить</button>
    </div>`;
  } else if (isStaff) {
    ownerBar = `<div class="post-owner-actions">
      <button id="btnHidePost">${post.is_hidden ? 'Показать' : 'Скрыть'}</button>
      <button id="btnAdminDelete">Удалить (админ)</button>
    </div>`;
  }

  $('postView').innerHTML = `
    <button class="back-btn" id="btnBack">← Назад к ленте</button>
    <div class="post-view">
      <div class="post-head">
        <span class="post-type ${post.type}">${typeLabel}</span>
        <span class="${authorClass}">${authorText}</span>
        <span class="post-time">${fmt(post.created_at)}${edited}</span>
      </div>
      <div class="post-body">${esc(post.body)}</div>
      ${ownerBar}
      <div class="comments-wrap">${commentsHtml}</div>
    </div>`;

  $('btnBack').onclick = () => App.go('feed');

  if ($('btnEditOwn')) {
    $('btnEditOwn').onclick = () => openCreateModal(post.type, post);
  }
  if ($('btnDeleteOwn')) {
    $('btnDeleteOwn').onclick = async () => {
      if (!confirm('Удалить запись?')) return;
      try {
        await api('/posts/' + post.id, { method: 'DELETE' });
        App.go('feed');
      } catch (e) { alert(e.message); }
    };
  }
  if ($('btnAdminDelete')) {
    $('btnAdminDelete').onclick = async () => {
      if (!confirm('Удалить запись (админ)?')) return;
      try {
        await api('/posts/' + post.id, { method: 'DELETE' });
        App.go('feed');
      } catch (e) { alert(e.message); }
    };
  }
  if ($('btnHidePost')) {
    $('btnHidePost').onclick = async () => {
      try {
        await api('/posts/' + post.id + '/hide', { method: 'POST' });
        loadPost(post.id);
      } catch (e) { alert(e.message); }
    };
  }

  if ($('btnSendComment')) {
    $('btnSendComment').onclick = sendComment;
    const ta = $('newCommentInput');
    ta.oninput = () => $('commentCounter').textContent = ta.value.length + ' / 500';
  }

  bindCommentEvents();
}

function renderComment(post, c, canPin) {
  const myId = state.user ? state.user.id : null;
  const isMe = myId && c.user_id === myId;
  const isPostAuthor = post.user_id && c.user_id === post.user_id;
  const role = c.author_role || 'user';

  let avatarClass = 'comment-avatar';
  if (role === 'main_admin') avatarClass += ' main_admin';
  else if (role === 'admin') avatarClass += ' admin';
  else if (role === 'support') avatarClass += ' support';

  let badges = '';
  if (role === 'main_admin') badges += `<span class="comment-badge main_admin">главный админ</span>`;
  else if (role === 'admin') badges += `<span class="comment-badge admin">админ</span>`;
  else if (role === 'support') badges += `<span class="comment-badge support">поддержка</span>`;
  else if (isPostAuthor) badges += `<span class="comment-badge author">автор</span>`;

  if (isMe) badges += `<span class="comment-badge me">вы</span>`;
  if (c.pinned) badges += `<span class="comment-badge pin">📌 закреплён</span>`;
  if (c.edited_at) badges += `<span class="comment-badge edited">изменено</span>`;

  const edited = c.edited_at ? ` · изменено ${fmt(c.edited_at)}` : '';
  const isEditing = state.editingCommentId === c.id;

  let body;
  if (isEditing) {
    body = `<div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">
      <input type="text" id="editCommentInput" value="${esc(c.body)}" maxlength="500"
        style="flex:1;min-width:180px;padding:10px;background:var(--bg);border:1px solid var(--border-2);border-radius:8px;color:var(--text);font-size:16px;outline:none">
      <button data-action="save-comment" data-id="${c.id}"
        style="padding:10px 16px;background:var(--accent);border:none;border-radius:8px;color:#000;font-weight:600;cursor:pointer">Сохранить</button>
      <button data-action="cancel-edit"
        style="padding:10px 16px;background:transparent;border:1px solid var(--border-2);color:var(--text-dim);border-radius:8px;cursor:pointer">Отмена</button>
    </div>`;
  } else {
    body = `<div class="comment-text">${esc(c.body)}</div>`;

    const actions = [];
    if (isMe) {
      actions.push(`<button data-action="edit-comment" data-id="${c.id}">Изменить</button>`);
      actions.push(`<button data-action="delete-comment" data-id="${c.id}">Удалить</button>`);
    } else if (state.user && ['main_admin', 'admin'].includes(state.user.role)) {
      actions.push(`<button data-action="delete-comment" data-id="${c.id}">Удалить (админ)</button>`);
    }
    if (canPin) {
      actions.push(`<button data-action="pin-comment" data-id="${c.id}">${c.pinned ? '📌 Открепить' : '📌 Закрепить'}</button>`);
    }
    if (actions.length) {
      body += `<div class="comment-actions">${actions.join('')}</div>`;
    }
  }

  return `<div class="comment ${c.pinned ? 'pinned' : ''}" data-comment-id="${c.id}">
    <div class="${avatarClass}">${esc(firstLetter(c.author_name))}</div>
    <div class="comment-body">
      <div class="comment-head">
        <span class="comment-author">${esc(c.author_name)}</span>
        ${badges}
        <span class="comment-time">${fmt(c.created_at)}${edited}</span>
      </div>
      ${body}
    </div>
  </div>`;
}

function bindCommentEvents() {
  document.querySelectorAll('[data-action="edit-comment"]').forEach(b => {
    b.onclick = () => {
      state.editingCommentId = parseInt(b.dataset.id, 10);
      loadPost(state.currentPostId);
    };
  });

  document.querySelectorAll('[data-action="delete-comment"]').forEach(b => {
    b.onclick = async () => {
      if (!confirm('Удалить комментарий?')) return;
      try {
        await api('/comments/' + b.dataset.id, { method: 'DELETE' });
        loadPost(state.currentPostId);
      } catch (e) { alert(e.message); }
    };
  });

  document.querySelectorAll('[data-action="pin-comment"]').forEach(b => {
    b.onclick = async () => {
      try {
        await api('/comments/' + b.dataset.id + '/pin', { method: 'POST' });
        loadPost(state.currentPostId);
      } catch (e) { alert(e.message); }
    };
  });

  document.querySelectorAll('[data-action="save-comment"]').forEach(b => {
    b.onclick = async () => {
      const txt = $('editCommentInput').value.trim();
      if (!txt) return;
      try {
        await api('/comments/' + b.dataset.id, { method: 'PUT', body: { body: txt } });
        state.editingCommentId = null;
        loadPost(state.currentPostId);
      } catch (e) { alert(e.message); }
    };
  });

  document.querySelectorAll('[data-action="cancel-edit"]').forEach(b => {
    b.onclick = () => {
      state.editingCommentId = null;
      loadPost(state.currentPostId);
    };
  });
}

async function sendComment() {
  const ta = $('newCommentInput');
  const text = ta.value.trim();
  if (!text) return;
  try {
    await api(`/posts/${state.currentPostId}/comments`, { method: 'POST', body: { body: text } });
    loadPost(state.currentPostId);
  } catch (e) { alert(e.message); }
}

// ============ CREATE/EDIT POST MODAL ============
function openCreateModal(type, editPost) {
  state.editingType = type;
  state.editingPostId = editPost ? editPost.id : null;

  $('createTitle').textContent = editPost
    ? (type === 'secret' ? 'Редактировать секрет' : 'Редактировать историю')
    : (type === 'secret' ? 'Новый секрет' : 'Новая история');

  $('createSubtitle').textContent = editPost
    ? 'Измени поля и сохрани'
    : (type === 'secret' ? 'То, что скрыто внутри' : 'Что случилось с тобой');

  $('textLabel').textContent = type === 'secret' ? 'Секрет' : 'История из жизни';
  $('bodyText').value = editPost ? editPost.body : '';
  $('anonToggle').checked = editPost ? editPost.is_anon : true;
  $('commentsToggle').checked = editPost ? editPost.allow_comments : true;
  $('btnSavePost').textContent = editPost ? 'Сохранить изменения' : 'Опубликовать';
  $('formMsg').textContent = '';
  updateAuthorPreview();
  $('createModal').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeCreateModal() {
  $('createModal').classList.add('hidden');
  document.body.style.overflow = '';
  state.editingPostId = null;
}

function updateAuthorPreview() {
  const prev = $('authorPreview');
  if ($('anonToggle').checked) {
    prev.style.display = 'none';
  } else {
    prev.style.display = 'flex';
    $('authorValue').textContent = state.user ? state.user.login : '—';
  }
}

async function savePost() {
  const body = $('bodyText').value.trim();
  const isAnon = $('anonToggle').checked;
  const allowComments = $('commentsToggle').checked;

  if (body.length < 2) {
    $('formMsg').textContent = 'Слишком короткий текст';
    $('formMsg').className = 'form-msg error';
    return;
  }

  try {
    if (state.editingPostId) {
      await api('/posts/' + state.editingPostId, {
        method: 'PUT',
        body: { body, isAnon, allowComments }
      });
      closeCreateModal();
      loadPost(state.editingPostId);
    } else {
      await api('/posts', {
        method: 'POST',
        body: { type: state.editingType, body, isAnon, allowComments }
      });
      closeCreateModal();
      App.go('feed');
    }
  } catch (e) {
    $('formMsg').textContent = e.message;
    $('formMsg').className = 'form-msg error';
  }
}

// ============ PROFILE ============
// ============ PROFILE ============
async function loadProfile(tab = 'secrets') {
  try {
    const d = await api('/posts?mine=1');
    const mine = d.posts || [];
    const mySecrets = mine.filter(p => p.type === 'secret');
    const myStories = mine.filter(p => p.type === 'story');
    const myComments = mine.reduce((acc, p) => acc + (p.comments_count || 0), 0);

    $('profileView').innerHTML = `
      <div class="profile-head">
        <div class="profile-avatar">${esc(firstLetter(state.user.login))}</div>
        <div class="profile-info">
          <h2>${esc(state.user.login)} ${state.user.role !== 'user' ? `<span class="role-tag ${state.user.role}">${esc(ROLE_SHORT[state.user.role])}</span>` : ''}</h2>
          <div class="meta">Секретов: ${mySecrets.length} · Историй: ${myStories.length} · Комментариев: ${myComments}</div>
        </div>
      </div>
      <div class="profile-tabs">
        <button class="profile-tab ${tab === 'secrets' ? 'active' : ''}" data-ptab="secrets">Мои секреты <span class="tab-count">${mySecrets.length}</span></button>
        <button class="profile-tab ${tab === 'stories' ? 'active' : ''}" data-ptab="stories">Мои истории <span class="tab-count">${myStories.length}</span></button>
      </div>
      <div class="profile-list">${
        (tab === 'secrets' ? mySecrets : myStories).map(p => `
          <div class="profile-post-item" data-id="${p.id}">
            <div class="item-head">
              <span class="post-type ${p.type}">${p.type === 'secret' ? 'Секрет' : 'История'}</span>
              <span class="post-author">${p.is_anon ? 'Анонимно' : esc(p.author_name)}</span>
              <span class="post-time" style="margin-left:auto">${fmt(p.created_at)}</span>
            </div>
            <div class="item-body">${esc(p.body)}</div>
          </div>`).join('') || '<div class="empty">Пусто</div>'
      }</div>`;

    document.querySelectorAll('.profile-tab').forEach(b => {
      b.onclick = () => loadProfile(b.dataset.ptab);
    });
    document.querySelectorAll('.profile-post-item').forEach(el => {
      el.onclick = () => App.go('post', parseInt(el.dataset.id, 10));
    });
  } catch (e) {
    console.error(e);
    $('profileView').innerHTML = `<div class="empty">Ошибка: ${esc(e.message)}</div>`;
  }
}

// ============ STAFF ============
async function loadStaff() {
  try {
    const d = await api('/staff');

    let form = '';
    if (state.user.role === 'main_admin') {
      form = `<div class="add-staff-form">
        <input type="text" id="staffLogin" placeholder="Логин пользователя" maxlength="20">
        <select id="staffRole">
          <option value="admin">Админ</option>
          <option value="support">Поддержка</option>
        </select>
        <button id="btnAddStaff">Назначить</button>
      </div>`;
    }

    const items = d.staff.map(s => `
      <div class="staff-item">
        <span class="login">${esc(s.login)}</span>
        <span class="role-tag ${s.role}">${esc(ROLE_SHORT[s.role])}</span>
        ${s.is_banned ? '<span class="role-tag" style="background:rgba(239,68,68,.15);color:var(--red)">забанен</span>' : ''}
        ${state.user.role === 'main_admin' && s.role !== 'main_admin' ? `
          <div class="actions">
            <button data-login="${esc(s.login)}" data-action="remove-staff">Снять роль</button>
            <button data-login="${esc(s.login)}" data-action="${s.is_banned ? 'unban' : 'ban'}">${s.is_banned ? 'Разбанить' : 'Забанить'}</button>
          </div>` : ''}
      </div>`).join('') || '<div class="empty">Персонала пока нет</div>';

    $('staffView').innerHTML = `
      <h2 style="font-size:20px;margin-bottom:20px">Персонал</h2>
      ${form}
      ${items}`;

    if ($('btnAddStaff')) {
      $('btnAddStaff').onclick = async () => {
        const login = $('staffLogin').value.trim();
        const role = $('staffRole').value;
        try {
          await api('/staff', { method: 'POST', body: { login, role } });
          loadStaff();
        } catch (e) { alert(e.message); }
      };
    }

    document.querySelectorAll('[data-action="remove-staff"]').forEach(b => {
      b.onclick = async () => {
        if (!confirm('Снять роль?')) return;
        try {
          await api('/staff/' + b.dataset.login, { method: 'DELETE' });
          loadStaff();
        } catch (e) { alert(e.message); }
      };
    });

    document.querySelectorAll('[data-action="ban"]').forEach(b => {
      b.onclick = async () => {
        const reason = prompt('Причина бана:', 'Нарушение правил');
        if (reason === null) return;
        const days = parseInt(prompt('На сколько дней? (0 = навсегда)', '7') || '7', 10);
        try {
          await api('/users/' + b.dataset.login + '/ban', {
            method: 'POST',
            body: { reason, days }
          });
          loadStaff();
        } catch (e) { alert(e.message); }
      };
    });

    document.querySelectorAll('[data-action="unban"]').forEach(b => {
      b.onclick = async () => {
        try {
          await api('/users/' + b.dataset.login + '/unban', { method: 'POST' });
          loadStaff();
        } catch (e) { alert(e.message); }
      };
    });
  } catch (e) { console.error(e); }
}

// ============ MODERATION ============
async function loadModeration() {
  try {
    const d = await api('/hidden-posts');
    const items = d.posts.map(p => `
      <div class="profile-post-item">
        <div class="item-head">
          <span class="post-type ${p.type}">${p.type === 'secret' ? 'Секрет' : 'История'}</span>
          <span class="post-author">${esc(p.author_name)}</span>
          <span class="post-time" style="margin-left:auto">${fmt(p.created_at)}</span>
        </div>
        <div class="item-body">${esc(p.body)}</div>
        <div style="margin-top:10px;display:flex;gap:8px">
          <button class="btn-save" data-action="unhide-post" data-id="${p.id}" style="padding:8px 14px;border:none;border-radius:8px;font-weight:600;cursor:pointer;font-family:inherit">Показать снова</button>
        </div>
      </div>`).join('') || '<div class="empty">Скрытых постов нет</div>';

    $('modView').innerHTML = `<h2 style="font-size:20px;margin-bottom:20px">Скрытые посты</h2>${items}`;

    document.querySelectorAll('[data-action="unhide-post"]').forEach(b => {
      b.onclick = async () => {
        try {
          await api('/posts/' + b.dataset.id + '/hide', { method: 'POST' });
          loadModeration();
        } catch (e) { alert(e.message); }
      };
    });
  } catch (e) { console.error(e); }
}

// ============ SUPPORT ============
function openSupport() {
  $('supportModal').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  showSupportMain();
}

function closeSupport() {
  $('supportModal').classList.add('hidden');
  document.body.style.overflow = '';
  state.currentTicketId = null;
  if (state.supportPollTimer) {
    clearInterval(state.supportPollTimer);
    state.supportPollTimer = null;
  }
}

function showSupportMain() {
  $('supportTicketForm').classList.add('hidden');
  $('supportTicketsList').classList.add('hidden');
  $('supportTicketChat').classList.add('hidden');
  $('supportTicketForm').classList.remove('hidden');
  $('ticketSubject').value = '';
  $('ticketReason').value = '';
  $('ticketMsg').textContent = '';
}

async function sendTicket() {
  const subject = $('ticketSubject').value.trim();
  const reason = $('ticketReason').value.trim();
  const priority = $('ticketPriority') ? $('ticketPriority').value : 'normal';

  if (subject.length < 3) {
    $('ticketMsg').textContent = 'Тема минимум 3 символа';
    $('ticketMsg').className = 'form-msg error';
    return;
  }
  if (reason.length < 5) {
    $('ticketMsg').textContent = 'Опиши подробнее';
    $('ticketMsg').className = 'form-msg error';
    return;
  }

  try {
    const d = await api('/tickets', { method: 'POST', body: { subject, reason, priority } });
    state.currentTicketId = d.id;
    showTicketChat(d.id);
  } catch (e) {
    $('ticketMsg').textContent = e.message;
    $('ticketMsg').className = 'form-msg error';
  }
}

async function showTicketChat(id) {
  state.currentTicketId = id;
  $('supportTicketForm').classList.add('hidden');
  $('supportTicketsList').classList.add('hidden');
  $('supportTicketChat').classList.remove('hidden');

  async function render() {
    try {
      const d = await api('/tickets/' + id);
      const isStaff = ['main_admin', 'admin', 'support'].includes(state.user.role);

      const msgs = d.messages.map(m => {
        const mine = state.user && m.user_id === state.user.id;
        const roleTag = m.author_role !== 'user'
          ? `<span class="role-tag ${m.author_role}">${esc(ROLE_SHORT[m.author_role])}</span>`
          : '';
        return `<div class="chat-msg ${mine ? 'mine' : 'theirs'}">
          <div class="who">${esc(m.author_name)} ${roleTag}</div>
          ${esc(m.body)}
          <div style="font-size:10px;color:var(--text-mute);margin-top:4px">${fmt(m.created_at)}</div>
        </div>`;
      }).join('');

      $('supportTicketChat').innerHTML = `
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap">
          <button class="back-btn" id="btnBackTickets" style="margin:0">← К списку</button>
          <span style="font-size:12px;color:var(--text-mute)">Тикет #${d.ticket.id} · ${d.ticket.status === 'open' ? 'открыт' : 'закрыт'}</span>
        </div>
        <h3 style="font-size:16px;margin-bottom:6px">${esc(d.ticket.subject)}</h3>
        <div style="font-size:11px;color:var(--text-mute);margin-bottom:14px">Причина: ${esc(d.ticket.reason)}</div>
        <div class="chat-box" id="chatBox">${msgs || '<div class="empty">Начните переписку</div>'}</div>
        <div class="chat-input">
          <input type="text" id="ticketMsgInput" placeholder="Сообщение..." maxlength="1000">
          <button id="btnSendTicketMsg">Отправить</button>
        </div>
        ${isStaff && d.ticket.status === 'open' ? `<div style="margin-top:10px;text-align:right"><button id="btnCloseTicket" style="padding:8px 14px;background:transparent;border:1px solid var(--border-2);color:var(--text-dim);border-radius:8px;cursor:pointer;font-family:inherit">Закрыть тикет</button></div>` : ''}`;

      $('btnBackTickets').onclick = () => {
        if (isStaff) loadTicketsList();
        else loadMyTickets();
      };

      const send = async () => {
        const txt = $('ticketMsgInput').value.trim();
        if (!txt) return;
        try {
          await api(`/tickets/${id}/messages`, { method: 'POST', body: { body: txt } });
          $('ticketMsgInput').value = '';
          render();
        } catch (e) { alert(e.message); }
      };

      $('btnSendTicketMsg').onclick = send;
      $('ticketMsgInput').onkeydown = e => {
        if (e.key === 'Enter') { e.preventDefault(); send(); }
      };

      if ($('btnCloseTicket')) {
        $('btnCloseTicket').onclick = async () => {
          try {
            await api(`/tickets/${id}/status`, { method: 'PUT', body: { status: 'closed' } });
            if (isStaff) loadTicketsList();
            else closeSupport();
          } catch (e) { alert(e.message); }
        };
      }

      const box = $('chatBox');
      if (box) box.scrollTop = box.scrollHeight;
    } catch (e) { console.error(e); }
  }

  await render();

  if (state.supportPollTimer) clearInterval(state.supportPollTimer);
  state.supportPollTimer = setInterval(() => {
    if ($('supportModal').classList.contains('hidden')) {
      clearInterval(state.supportPollTimer);
      return;
    }
    if (state.currentTicketId === id) render();
  }, 5000);
}

async function loadTicketsList() {
  try {
    const d = await api('/tickets?status=open');
    $('supportTicketForm').classList.add('hidden');
    $('supportTicketChat').classList.add('hidden');
    $('supportTicketsList').classList.remove('hidden');

    const priorityLabel = { low: 'низкий', normal: 'обычный', high: 'срочный' };

    const items = d.tickets.map(t => `
      <div class="ticket-item" data-id="${t.id}">
        <div class="head">
          <span class="subject">#${t.id} ${esc(t.subject)}</span>
          <span class="status ${t.status}">${t.status === 'open' ? 'открыт' : 'закрыт'}</span>
        </div>
        <div class="meta">От ${esc(t.user_login || 'удалён')} · приоритет: ${priorityLabel[t.priority] || 'обычный'} · ${fmt(t.updated_at)} · ${t.messages_count} сообщ.</div>
      </div>`).join('') || '<div class="empty">Открытых тикетов нет</div>';

    $('supportTicketsList').innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
        <h3 style="font-size:16px">Обращения</h3>
        <button id="btnBackSupportMain" style="background:transparent;border:1px solid var(--border-2);color:var(--text-dim);padding:6px 12px;border-radius:8px;cursor:pointer;font-family:inherit;font-size:12px">Закрыть</button>
      </div>
      ${items}`;

    $('btnBackSupportMain').onclick = closeSupport;
    document.querySelectorAll('.ticket-item').forEach(el => {
      el.onclick = () => showTicketChat(parseInt(el.dataset.id, 10));
    });
  } catch (e) { console.error(e); }
}

async function loadMyTickets() {
  try {
    const d = await api('/tickets/my');
    $('supportTicketForm').classList.add('hidden');
    $('supportTicketChat').classList.add('hidden');
    $('supportTicketsList').classList.remove('hidden');

    const items = d.tickets.map(t => `
      <div class="ticket-item" data-id="${t.id}">
        <div class="head">
          <span class="subject">#${t.id} ${esc(t.subject)}</span>
          <span class="status ${t.status}">${t.status === 'open' ? 'открыт' : 'закрыт'}</span>
        </div>
        <div class="meta">${fmt(t.updated_at)} · ${t.messages_count} сообщ.</div>
      </div>`).join('') || '<div class="empty">Ты ещё не писал в поддержку</div>';

    $('supportTicketsList').innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;gap:10px;flex-wrap:wrap">
        <h3 style="font-size:16px">Мои обращения</h3>
        <div style="display:flex;gap:8px">
          <button id="btnNewTicket" style="background:var(--accent);border:none;color:#000;padding:8px 14px;border-radius:8px;cursor:pointer;font-family:inherit;font-size:12px;font-weight:600">Новое</button>
          <button id="btnCloseList" style="background:transparent;border:1px solid var(--border-2);color:var(--text-dim);padding:8px 14px;border-radius:8px;cursor:pointer;font-family:inherit;font-size:12px">Закрыть</button>
        </div>
      </div>
      ${items}`;

    $('btnNewTicket').onclick = showSupportMain;
    $('btnCloseList').onclick = closeSupport;
    document.querySelectorAll('.ticket-item').forEach(el => {
      el.onclick = () => showTicketChat(parseInt(el.dataset.id, 10));
    });
  } catch (e) { console.error(e); }
}

// ============ УВЕДОМЛЕНИЯ ============
function startPolling() {
  if (!state.user) return;
  const staffRoles = ['main_admin', 'admin', 'support'];

  if (state.notifyPollTimer) clearInterval(state.notifyPollTimer);

  if (staffRoles.includes(state.user.role)) {
    const poll = async () => {
      try {
        const d = await api('/tickets/notify');
        const badge = $('supportBadge');
        if (d.open > 0) {
          badge.textContent = d.open;
          badge.classList.remove('hidden');
        } else {
          badge.classList.add('hidden');
        }
      } catch (e) {}
    };
    poll();
    state.notifyPollTimer = setInterval(poll, 15000);
  } else {
    $('supportBadge').classList.add('hidden');
  }
}

function stopPolling() {
  if (state.supportPollTimer) clearInterval(state.supportPollTimer);
  if (state.notifyPollTimer) clearInterval(state.notifyPollTimer);
}

// ============ НАСТРОЙКИ АККАУНТА ============
function openSettings() {
  $('settingsModal').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  $('oldPass').value = '';
  $('newPass').value = '';
  $('delPass').value = '';
  $('passMsg').textContent = '';
}

function closeSettings() {
  $('settingsModal').classList.add('hidden');
  document.body.style.overflow = '';
}

async function changePassword() {
  const oldPassword = $('oldPass').value;
  const newPassword = $('newPass').value;

  if (newPassword.length < 8) {
    $('passMsg').textContent = 'Пароль от 8 символов';
    $('passMsg').className = 'form-msg error';
    return;
  }

  try {
    await api('/change-password', { method: 'POST', body: { oldPassword, newPassword } });
    $('passMsg').textContent = 'Пароль изменён. Войди заново.';
    $('passMsg').className = 'form-msg ok';
    setTimeout(() => {
      state.user = null;
      renderAuth();
      closeSettings();
    }, 1500);
  } catch (e) {
    $('passMsg').textContent = e.message;
    $('passMsg').className = 'form-msg error';
  }
}

async function exportData() {
  try {
    const d = await api('/export');
    const blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `whisper-export-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) { alert(e.message); }
}

async function deleteAccount() {
  const password = $('delPass').value;
  if (!password) { alert('Введи пароль'); return; }
  if (!confirm('Удалить аккаунт? Действие необратимо.')) return;
  if (!confirm('Точно удалить? Все посты и комментарии исчезнут.')) return;

  try {
    await api('/account', { method: 'DELETE', body: { password } });
    state.user = null;
    closeSettings();
    renderAuth();
  } catch (e) { alert(e.message); }
}

// ============ INIT ============
async function init() {
  try {
    const d = await api('/me');
    state.user = d.user;
  } catch (e) {}

  renderAuth();

  // Auth
  $('tabLogin').onclick = () => setAuthMode('login');
  $('tabRegister').onclick = () => setAuthMode('register');
  $('authBtn').onclick = doAuth;
  $('passInput').onkeydown = e => { if (e.key === 'Enter') doAuth(); };
  $('pass2Input').onkeydown = e => { if (e.key === 'Enter') doAuth(); };

  // Nav
  $('navFeed').onclick = () => App.go('feed');
  $('navProfile').onclick = () => App.go('profile');
  $('navStaff').onclick = () => App.go('staff');
  $('navMod').onclick = () => App.go('mod');

  // Filters
  document.querySelectorAll('.filter').forEach(b => {
    b.onclick = () => {
      document.querySelectorAll('.filter').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      state.filter = b.dataset.f;
      loadFeed();
    };
  });

  // Actions
  $('btnNewSecret').onclick = () => openCreateModal('secret');
  $('btnNewStory').onclick = () => openCreateModal('story');
  $('btnSavePost').onclick = savePost;
  $('btnCancelModal').onclick = closeCreateModal;
  $('anonToggle').onchange = updateAuthorPreview;

  // Support
  $('supportFab').onclick = () => {
    if (!state.user) return;
    openSupport();
    const staffRoles = ['main_admin', 'admin', 'support'];
    if (staffRoles.includes(state.user.role)) loadTicketsList();
    else loadMyTickets();
  };
  $('btnSendTicket').onclick = sendTicket;
  $('btnSupportClose').onclick = closeSupport;

  // Settings
  $('btnChangePass').onclick = changePassword;
  $('btnExport').onclick = exportData;
  $('btnDeleteAccount').onclick = deleteAccount;
  $('btnCloseSettings').onclick = closeSettings;

  // Turnstile
  if (window.TURNSTILE_ENABLED) {
    $('turnstileWrap').style.display = 'block';
  }

  if (state.user) App.go('feed');
}

init();