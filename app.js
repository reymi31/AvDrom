(function () {
  const state = {
    user: null,
    initialized: false,
    initPromise: null,
  };

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function setHTML(id, value) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = value;
  }

  function show(el, shouldShow) {
    if (!el) return;
    el.classList.toggle('hidden', !shouldShow);
  }

  function isEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());
  }

  function normalizeErrorMessage(err) {
    if (!err) return 'Неизвестная ошибка';
    if (typeof err === 'string') return err;
    if (err.message) return err.message;
    return 'Ошибка запроса';
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function ensureMinDuration(startMs, minMs) {
    const elapsed = Date.now() - startMs;
    const remaining = minMs - elapsed;
    if (remaining > 0) {
      await sleep(remaining);
    }
  }

  async function apiFetch(url, options) {
    const response = await fetch(url, options);
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      const message = text || `Ошибка ${response.status}`;
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return response;
  }

  async function apiJson(url, options) {
    const response = await apiFetch(url, options);
    return response.json();
  }

  async function logout() {
    await fetch('/api/auth/logout', { method: 'POST' }).catch(() => null);
    window.location.href = '/';
  }

  function updateHeader() {
    const authLink = document.getElementById('auth-link');
    const userChip = document.getElementById('user-chip');
    const privateEls = document.querySelectorAll('[data-private]');
    const adminEls = document.querySelectorAll('[data-admin]');

    const isAuthed = Boolean(state.user);
    privateEls.forEach((el) => el.classList.toggle('hidden', !isAuthed));
    adminEls.forEach((el) =>
      el.classList.toggle('hidden', !(isAuthed && state.user && state.user.role === 'admin'))
    );

    if (userChip) {
      userChip.textContent = isAuthed ? state.user.name : '';
      userChip.classList.toggle('hidden', !isAuthed);
    }

    if (authLink) {
      if (isAuthed) {
        authLink.textContent = 'Выйти';
        authLink.setAttribute('href', '#');
        authLink.onclick = async (e) => {
          e.preventDefault();
          await logout();
        };
      } else {
        authLink.textContent = 'Войти';
        authLink.setAttribute('href', '/auth/login');
        authLink.onclick = null;
      }
    }
  }

  async function initAuth() {
    if (state.initPromise) return state.initPromise;

    state.initPromise = (async () => {
      try {
        const response = await fetch('/api/auth/me');
        state.user = response.ok ? await response.json() : null;
      } catch {
        state.user = null;
      }
      state.initialized = true;
      updateHeader();
      return state.user;
    })();

    return state.initPromise;
  }

  function showError(containerId, message) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.textContent = message;
    container.classList.remove('hidden');
  }

  function clearError(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.textContent = '';
    container.classList.add('hidden');
  }

  function formatPrice(value) {
    const num = Number(value);
    if (!Number.isFinite(num)) return String(value ?? '');
    return num.toLocaleString('ru-RU');
  }

  async function loadContent(page) {
    return apiJson(`/api/content/${encodeURIComponent(page)}`);
  }

  window.Avdrom = {
    get user() {
      return state.user;
    },
    initAuth,
    updateHeader,
    apiFetch,
    apiJson,
    loadContent,
    logout,
    setText,
    setHTML,
    showError,
    clearError,
    isEmail,
    normalizeErrorMessage,
    formatPrice,
    sleep,
    ensureMinDuration,
  };
})();
