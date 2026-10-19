const form = document.getElementById('login-form');
const username = document.getElementById('username');
const password = document.getElementById('password');
const statusNode = document.getElementById('login-status');
const submitButton = document.getElementById('login-submit');
const submitLabel = document.querySelector('.login-submit-label');
const visibilityButton = document.getElementById('password-visibility');
const eyeShowIcon = document.getElementById('eye-show');
const eyeHideIcon = document.getElementById('eye-hide');
const capslockHint = document.getElementById('capslock-hint');
const captchaImage = document.getElementById('captcha-image');
const captchaSvg = document.getElementById('captcha-svg');
const captchaAnswer = document.getElementById('captcha-answer');
const tokenStorageKey = 'payloader-admin-access-token';
const jwtPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

let captchaToken = '';

const loadCaptcha = async () => {
  captchaToken = '';
  captchaSvg.textContent = '加载中…';
  try {
    const response = await fetch('/api/admin/captcha');
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.token !== 'string' || typeof body.svg !== 'string') {
      throw new Error(body.error || '验证码服务暂不可用');
    }
    captchaToken = body.token;
    captchaSvg.innerHTML = body.svg;
  } catch {
    captchaSvg.textContent = '点击重试';
  }
};

captchaImage.addEventListener('click', loadCaptcha);

const setStatus = (message, tone = '') => {
  statusNode.textContent = message;
  statusNode.dataset.tone = tone;
};

const setBusy = busy => {
  submitButton.disabled = busy;
  submitButton.classList.toggle('is-busy', busy);
  submitButton.setAttribute('aria-busy', String(busy));
  submitLabel.textContent = busy ? '登录中…' : '登录';
};

let passwordVisible = false;

const togglePasswordVisibility = event => {
  passwordVisible = !passwordVisible;
  password.type = passwordVisible ? 'text' : 'password';
  visibilityButton.setAttribute('aria-pressed', String(passwordVisible));
  visibilityButton.setAttribute('aria-label', passwordVisible ? '隐藏密码' : '显示密码');
  eyeShowIcon.hidden = passwordVisible;
  eyeHideIcon.hidden = !passwordVisible;
  // 键盘激活（detail=0）时保持焦点在按钮上，不打断 Tab 前进；指针点击才回焦输入框
  if (event.detail > 0) password.focus();
};

visibilityButton.addEventListener('click', togglePasswordVisibility);

const syncCapsLock = event => {
  if (typeof event.getModifierState !== 'function') return;
  capslockHint.hidden = !event.getModifierState('CapsLock');
};

password.addEventListener('keydown', syncCapsLock);
password.addEventListener('keyup', syncCapsLock);
// 点击进框时鼠标事件携带修饰键状态，覆盖 CapsLock 已开再聚焦的场景
password.addEventListener('click', syncCapsLock);
password.addEventListener('blur', () => {
  capslockHint.hidden = true;
});

form.addEventListener('submit', async event => {
  event.preventDefault();
  const payload = {
    username: username.value.trim(),
    password: password.value,
    captchaToken,
    captchaAnswer: captchaAnswer.value.trim(),
  };

  if (!payload.username || !payload.password) {
    setStatus('请输入账号和密码', 'error');
    if (!payload.username) {
      username.focus();
    } else {
      password.focus();
    }
    return;
  }
  if (!captchaToken) {
    setStatus('验证码尚未就绪，正在刷新，请稍候重试', 'error');
    loadCaptcha();
    return;
  }
  if (!payload.captchaAnswer) {
    setStatus('请输入图形验证码', 'error');
    captchaAnswer.focus();
    return;
  }

  setBusy(true);
  setStatus('');
  try {
    const response = await fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw Object.assign(new Error(body.error || `登录失败：HTTP ${response.status}`), {
        captchaInvalid: Boolean(body.captchaInvalid),
        credentialsInvalid: response.status === 401 && !body.captchaInvalid,
      });
    }
    if (body.tokenType !== 'Bearer' || !jwtPattern.test(String(body.accessToken || ''))) {
      throw new Error('服务器返回的管理员令牌格式无效');
    }
    sessionStorage.setItem(tokenStorageKey, body.accessToken);
    if (body.mustChangePassword) {
      setStatus('登录成功：当前仍在使用默认密码，正在进入密码修改…', 'ok');
    }
    window.location.replace('/admin');
  } catch (error) {
    password.value = '';
    // 验证码服务端即焚：失败后图片必然换新，旧答案一律作废清空，避免残留旧值重提交必错
    captchaAnswer.value = '';
    // 密码错误回密码框；验证码错误与其余失败回验证码框（下一轮都要先对码）
    (error.credentialsInvalid ? password : captchaAnswer).focus();
    const reason = error instanceof Error && error.message ? error.message : '登录失败，请稍后重试';
    setStatus(`${reason}；已更换新验证码`, 'error');
    // 验证码服务端即焚：无论失败原因，下一次提交都需要新验证码
    loadCaptcha();
  } finally {
    setBusy(false);
  }
});

const restoreExistingSession = async () => {
  const token = sessionStorage.getItem(tokenStorageKey) || '';
  if (!jwtPattern.test(token)) {
    sessionStorage.removeItem(tokenStorageKey);
    return;
  }
  try {
    const response = await fetch('/api/admin/session', {
      headers: { authorization: `Bearer ${token}` },
    });
    if (response.ok) {
      window.location.replace('/admin');
      return;
    }
  } catch {
    // Keep the login form usable when the session probe is unavailable.
  }
  sessionStorage.removeItem(tokenStorageKey);
};

restoreExistingSession();
loadCaptcha();
