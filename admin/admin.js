const modules = {
  settings: {
    title: '站点设置',
    api: '/api/admin/settings',
    reset: 'settings',
  },
  payloads: {
    title: 'Payload 管理',
    api: '/api/admin/payloads',
    reset: 'payloads',
  },
  tools: {
    title: '工具命令管理',
    api: '/api/admin/tools',
    reset: 'tools',
  },
  navigation: {
    title: '导航树管理',
    api: '/api/admin/navigation',
    reset: 'navigation',
  },
  exploits: {
    title: 'EXP 管理',
    api: '/api/admin/exploits',
    reset: 'exploits',
  },
  clientBuilds: {
    title: '客户端生成',
    api: '/api/admin/client-builds',
  },
  updates: {
    title: '系统更新',
    api: '/api/admin/version-status',
  },
  account: {
    title: '账号安全',
    api: '/api/admin/credentials',
  },
};

const itemListPageSize = 120;
const adminTokenStorageKey = 'payloader-admin-access-token';

const state = {
  module: 'settings',
  // EXP 管理单模块分区：items=条目管理（主体），tree=分类树管理（模块内分区，不再独立成模块）
  expSection: 'items',
  mustChangePassword: false,
  settings: null,
  payloads: [],
  tools: [],
  navigation: [],
  exploits: [],
  exploitNavigation: [],
  selectedId: null,
  query: '',
  group: '',
  visibleItemLimit: itemListPageSize,
  draft: null,
  dirty: false,
  loading: true,
  saving: false,
  mobileView: 'editor',
  rendering: false,
  sectionState: {},
  editorSections: [],
  activeSectionTitle: null,
  logoUploadMeta: null,
  importOpen: false,
  importData: null,
  importFileName: '',
  importMode: 'merge',
  importPreview: null,
  importResult: null,
  importing: false,
  importError: '',
  clientBuildStatus: null,
  clientBuildSelectedTargets: null,
  clientBuildLoading: false,
  clientBuildGenerating: false,
  versionStatus: null,
  versionChecking: false,
  account: null,
  accessToken: sessionStorage.getItem(adminTokenStorageKey) || '',
  navCollapsed: localStorage.getItem('payloader-admin-nav-collapsed') === '1',
};

const $ = id => document.getElementById(id);
const apiUrl = path => `${window.location.protocol}//${window.location.host}${path}`;
const clone = value => JSON.parse(JSON.stringify(value ?? null));
const text = value => {
  if (typeof value === 'string') return { zh: value, en: value };
  if (value && typeof value === 'object') return { zh: value.zh || '', en: value.en || value.zh || '' };
  return { zh: '', en: '' };
};
const getText = value => {
  const t = text(value);
  return t.zh || t.en || '';
};
const makeText = (zh, en) => ({ zh: String(zh || '').trim(), en: String(en || '').trim() });
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#039;',
}[char]));
const splitLines = value => String(value || '').split(/\r?\n/).map(item => item.trim()).filter(Boolean);
const splitTags = value => String(value || '').split(/[,，]/).map(item => item.trim()).filter(Boolean);
const joinTextLines = list => (Array.isArray(list) ? list.map(getText).filter(Boolean).join('\n') : '');
const joinPlainLines = list => (Array.isArray(list) ? list.filter(Boolean).join('\n') : '');
const toTextList = value => splitLines(value).map(item => makeText(item, item));
const maxLogoBytes = 1_048_576;
const maxLogoDimension = 1024;
const maxImportBytes = 20 * 1024 * 1024;
const acceptedLogoTypes = new Set(['image/png', 'image/jpeg', 'image/webp']);
const acceptedLogoExtensions = new Set(['png', 'jpg', 'jpeg', 'webp']);
const logoTypeLabels = {
  'image/png': 'PNG',
  'image/jpeg': 'JPG',
  'image/webp': 'WebP',
};
const safeLogoUrlPattern = /^\/uploads\/logo\/logo-[a-zA-Z0-9.-]+\.(png|jpe?g|webp)$/;
const sanitizeLogoUrl = value => {
  const logoUrl = String(value || '').trim();
  return safeLogoUrlPattern.test(logoUrl) ? logoUrl : '';
};
const formatBytes = value => {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 KB';
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(bytes >= 1024 * 100 ? 0 : 1)} KB`;
};
const logoFileExtension = file => String(file?.name || '').split('.').pop()?.toLowerCase() || '';
const renderLogoUploadMeta = logoUrl => {
  const meta = state.logoUploadMeta;
  if (!meta || sanitizeLogoUrl(meta.logoUrl) !== logoUrl) return '';
  return `
    <div class="logo-upload-result" role="status">
      <strong>已上传，待保存站点设置</strong>
      <span>${escapeHtml(meta.fileName || 'Logo 图片')} · ${escapeHtml(logoTypeLabels[meta.mimeType] || meta.mimeType || '图片')} · ${escapeHtml(`${meta.width}x${meta.height}px`)} · ${escapeHtml(formatBytes(meta.size))}</span>
    </div>
  `;
};

const moduleConfig = () => modules[state.module];
// EXP 分类树资源 API（合并进 EXP 管理模块后不再有独立模块入口，仅分区使用）
const exploitNavigationApi = '/api/admin/exploit_navigation';
// EXP 管理单模块分区：tree 分区只切数据面（列表数据源/编辑器/保存 API），模块仍是 exploits
const isExpTreeSection = () => state.module === 'exploits' && state.expSection === 'tree';
const resourceStateKey = () => (isExpTreeSection() ? 'exploitNavigation' : state.module);
const resourceApi = () => (isExpTreeSection() ? exploitNavigationApi : moduleConfig().api);
const singletonModules = new Set(['settings', 'clientBuilds', 'updates', 'account']);
const isSingletonModule = () => singletonModules.has(state.module);
const activeItems = () => isSingletonModule() ? [] : (state[resourceStateKey()] || []);
const selectedItem = () => state.module === 'settings'
  ? state.settings
  : activeItems().find(item => item.id === state.selectedId) || null;
const moduleLabels = {
  settings: '全局配置',
  payloads: 'Payload',
  tools: '工具命令',
  navigation: '导航树',
  exploits: 'EXP',
};

moduleLabels.clientBuilds = '客户端生成';
moduleLabels.updates = '系统更新';

moduleLabels.account = '账号安全';

const syncNavCollapse = () => {
  document.body.dataset.navCollapsed = state.navCollapsed ? 'true' : 'false';
  const button = document.querySelector('.nav-collapse-btn');
  if (!button) return;
  button.setAttribute('aria-expanded', state.navCollapsed ? 'false' : 'true');
  const label = button.querySelector('strong');
  if (label) label.textContent = state.navCollapsed ? '展开' : '收起';
  button.setAttribute('aria-label', state.navCollapsed ? '展开后台模块导航' : '收起后台模块导航');
};

const ensureNavCollapseButton = () => {
  const sidebar = document.querySelector('.admin-sidebar');
  const nav = document.querySelector('.module-nav');
  if (!sidebar || !nav || document.querySelector('.nav-collapse-btn')) return;
  const button = document.createElement('button');
  button.className = 'nav-collapse-btn';
  button.type = 'button';
  button.dataset.action = 'toggle-admin-nav';
  button.innerHTML = '<span>模块导航</span><strong>收起</strong>';
  sidebar.insertBefore(button, nav);
  syncNavCollapse();
};

// ---- 应用内确认弹窗（F-19）：替代原生 confirm()，破坏性操作支持关键词输入二次确认 ----
const confirmModal = { open: false, resolve: null, requireText: '' };

const closeConfirmModal = result => {
  if (!confirmModal.open) return;
  confirmModal.open = false;
  confirmModal.requireText = '';
  const backdrop = $('confirm-modal');
  if (backdrop) {
    backdrop.classList.add('hidden');
    backdrop.setAttribute('aria-hidden', 'true');
  }
  const resolve = confirmModal.resolve;
  confirmModal.resolve = null;
  resolve?.(result === true);
};

const requestConfirm = ({
  title,
  messageHtml,
  confirmLabel = '确认',
  cancelLabel = '取消',
  danger = false,
  requireText = '',
}) => new Promise(resolve => {
  const backdrop = $('confirm-modal');
  if (!backdrop || confirmModal.open) {
    resolve(false);
    return;
  }
  confirmModal.open = true;
  confirmModal.resolve = resolve;
  confirmModal.requireText = String(requireText || '');
  $('confirm-modal-title').textContent = title;
  $('confirm-modal-message').innerHTML = messageHtml;
  const confirmButton = $('confirm-modal-confirm');
  confirmButton.textContent = confirmLabel;
  confirmButton.classList.toggle('danger-solid', danger);
  const gateInput = $('confirm-modal-gate-input');
  const needsGate = Boolean(confirmModal.requireText);
  $('confirm-modal-gate').classList.toggle('hidden', !needsGate);
  gateInput.value = '';
  confirmButton.disabled = needsGate;
  if (needsGate) $('confirm-modal-gate-keyword').textContent = confirmModal.requireText;
  $('confirm-modal-cancel').textContent = cancelLabel;
  backdrop.classList.remove('hidden');
  backdrop.setAttribute('aria-hidden', 'false');
  (needsGate ? gateInput : confirmButton).focus();
});

const confirmDiscard = async () => {
  if (!state.dirty) return true;
  return requestConfirm({
    title: '未保存修改',
    messageHtml: '当前表单有未保存修改，继续操作会丢失这些修改。',
    confirmLabel: '继续并丢弃修改',
    cancelLabel: '留在本页',
    danger: true,
  });
};

const notice = message => {
  const node = $('notice');
  node.textContent = message;
  node.classList.add('visible');
  clearTimeout(notice.timer);
  notice.timer = setTimeout(() => node.classList.remove('visible'), 2600);
};

const setDirty = dirty => {
  state.dirty = Boolean(dirty);
  updateTopbar();
};

const defaultMobileView = module => singletonModules.has(module) ? 'editor' : 'list';
const currentMobileView = () => isSingletonModule() ? 'editor' : state.mobileView;
const sectionKey = title => `${state.module}:${title}`;

const setMobileView = view => {
  state.mobileView = view === 'list' ? 'list' : 'editor';
  updateTopbar();
  requestAnimationFrame(() => {
    const target = currentMobileView() === 'editor' ? document.querySelector('.editor-panel') : $('list-panel');
    target?.scrollTo?.({ top: 0, behavior: 'smooth' });
  });
};

const sectionOpenDefault = (title, index) => {
  if (state.module !== 'settings') {
    return state.activeSectionTitle === title;
  }
  if (Object.prototype.hasOwnProperty.call(state.sectionState, sectionKey(title))) {
    return state.sectionState[sectionKey(title)];
  }
  const compact = window.matchMedia('(max-width: 860px)').matches;
  return !compact || state.module === 'settings' || index === 0;
};

const updateSaveState = () => {
  const node = $('save-state');
  if (!node) return;
  const readOnlyStatusModule = state.module === 'clientBuilds' || state.module === 'updates';
  node.className = `save-state${readOnlyStatusModule ? ' hidden' : ''}`;
  if (state.loading) {
    node.textContent = '正在加载';
    node.classList.add('loading');
  } else if (state.saving) {
    node.textContent = '保存中';
    node.classList.add('saving');
  } else if (state.dirty) {
    node.textContent = '有未保存修改';
    node.classList.add('dirty');
  } else {
    node.textContent = '已同步';
    node.classList.add('saved');
  }
  const mobileNode = $('mobile-save-state');
  if (mobileNode) {
    const stateClasses = [...node.classList].filter(name => name !== 'save-state').join(' ');
    mobileNode.className = `mobile-save-state ${stateClasses}`.trim();
    mobileNode.textContent = node.textContent;
  }
};

const redirectToLogin = () => {
  sessionStorage.removeItem(adminTokenStorageKey);
  state.accessToken = '';
  window.location.replace('/admin/login');
};

const adminFetch = async (url, options = {}) => {
  const method = String(options.method || 'GET').toUpperCase();
  const headers = { ...(options.headers || {}) };
  if (options.body !== undefined && !headers['content-type'] && !headers['Content-Type']) {
    headers['content-type'] = 'application/json';
  }
  if (state.accessToken) headers.authorization = `Bearer ${state.accessToken}`;
  return fetch(apiUrl(url), {
    ...options,
    method,
    headers,
  });
};

const api = async (url, options = {}) => {
  const response = await adminFetch(url, options);
  if (response.status === 401) {
    redirectToLogin();
    throw new Error('Session expired, please sign in again');
  }
  if (response.status === 403) {
    // 服务端强制改密闸门：任何端点返回 403+mustChangePassword 时切入强制改密模式
    const body = await response.clone().json().catch(() => null);
    if (body && body.mustChangePassword) {
      enterForcedPasswordChange();
      throw new Error(body.error || '请先修改默认管理员密码');
    }
  }
  if (!response.ok) {
    const body = await response.text();
    let message = body;
    try {
      const parsed = JSON.parse(body);
      message = parsed.error || message;
    } catch {
      // Plain text API errors are already readable.
    }
    throw new Error(message || `HTTP ${response.status}`);
  }
  return response.json();
};

const readResponseError = async response => {
  const body = await response.text();
  try {
    const parsed = JSON.parse(body);
    return parsed.error || body || `HTTP ${response.status}`;
  } catch {
    return body || `HTTP ${response.status}`;
  }
};

const importModeLabel = mode => mode === 'replace' ? '覆盖所选模块' : '合并更新';

const loadSession = async () => {
  const response = await adminFetch('/api/admin/session');
  if (response.status === 401) {
    redirectToLogin();
    throw new Error('Session expired, please sign in again');
  }
  if (!response.ok) throw new Error(await readResponseError(response));
  const body = await response.json();
  if (body && body.mustChangePassword) state.mustChangePassword = true;
  return body;
};

// 强制改密模式：锁死在账号安全模块，直到默认密码被修改（服务端 403 闸门的配套 UI）
const enterForcedPasswordChange = () => {
  if (!state.mustChangePassword) {
    state.mustChangePassword = true;
    state.draft = null;
    state.dirty = false;
    state.module = 'account';
    state.mobileView = defaultMobileView('account');
    render();
  }
  notice('检测到仍在使用默认管理员密码，请先在下方完成密码修改');
};

const logoutAdmin = async () => {
  try {
    await api('/api/admin/logout', { method: 'POST', body: JSON.stringify({}) });
  } catch {
    // Keep local cleanup deterministic even if the server request is interrupted.
  } finally {
    redirectToLogin();
  }
};

const renderImportSummary = summary => {
  if (!Array.isArray(summary) || !summary.length) {
    return '<div class="import-empty">没有可显示的导入模块。</div>';
  }
  return `
    <div class="import-summary-grid">
      ${summary.map(item => `
        <div class="import-summary-item ${item.included ? 'included' : 'excluded'}">
          <span>${escapeHtml(item.label || item.key)}</span>
          <strong>${Number(item.count || 0)}</strong>
          <small>${item.included ? '将导入' : '未包含'}</small>
        </div>
      `).join('')}
    </div>
  `;
};

const renderImportWarnings = warnings => {
  if (!Array.isArray(warnings) || !warnings.length) {
    return '<div class="import-ok">没有格式警告。</div>';
  }
  return `
    <ul class="import-warning-list">
      ${warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join('')}
    </ul>
  `;
};

const renderImportOutput = () => {
  const output = $('import-output');
  if (!output) return;
  if (state.importError) {
    output.innerHTML = `
      <div class="import-status error">
        <strong>导入文件无法使用</strong>
        <span>${escapeHtml(state.importError)}</span>
      </div>
    `;
    return;
  }
  if (state.importResult) {
    output.innerHTML = `
      <div class="import-status success">
        <strong>导入完成</strong>
        <span>已按「${escapeHtml(importModeLabel(state.importResult.mode))}」写入数据库，后台列表已刷新。</span>
      </div>
      ${renderImportSummary(state.importResult.summary)}
      ${renderImportWarnings(state.importResult.warnings)}
    `;
    return;
  }
  if (state.importPreview) {
    output.innerHTML = `
      <div class="import-status">
        <strong>预览已完成</strong>
        <span>确认数量和警告后，可以执行导入。</span>
      </div>
      ${renderImportSummary(state.importPreview.summary)}
      ${renderImportWarnings(state.importPreview.warnings)}
    `;
    return;
  }
  if (state.importData) {
    const keys = Object.keys(state.importData).slice(0, 8);
    const ignoredGuideKeys = ['guide', 'fieldReference', 'limits', 'instructions'].filter(key => Object.prototype.hasOwnProperty.call(state.importData, key));
    output.innerHTML = `
      <div class="import-status">
        <strong>文件已读取</strong>
        <span>${escapeHtml(state.importFileName)}，检测到字段：${escapeHtml(keys.join('、') || '无')}</span>
      </div>
      ${ignoredGuideKeys.length ? `
        <div class="import-status">
          <strong>说明字段会自动忽略</strong>
          <span>${escapeHtml(ignoredGuideKeys.join('、'))} 只用于指导填写，不会写入数据库。</span>
        </div>
      ` : ''}
    `;
    return;
  }
  output.innerHTML = '<div class="import-empty">选择 JSON 文件后，点击“预览文件”查看将导入的内容。</div>';
};

const renderImportModal = () => {
  const modal = $('import-modal');
  if (!modal) return;
  modal.classList.toggle('hidden', !state.importOpen);
  modal.setAttribute('aria-hidden', state.importOpen ? 'false' : 'true');
  document.body.dataset.importOpen = state.importOpen ? 'true' : 'false';

  const fileName = $('import-file-name');
  if (fileName) {
    fileName.textContent = state.importFileName || '尚未选择文件';
  }
  for (const input of document.querySelectorAll('input[name="import-mode"]')) {
    input.checked = input.value === state.importMode;
    input.disabled = state.importing;
  }

  const hasData = Boolean(state.importData);
  const hasPreview = Boolean(state.importPreview);
  const downloadButton = $('download-template');
  const previewButton = $('preview-import');
  const runButton = $('run-import');
  const closeButton = $('close-import');
  if (downloadButton) downloadButton.disabled = state.importing;
  if (previewButton) {
    previewButton.disabled = state.importing || !hasData;
    previewButton.textContent = state.importing ? '处理中' : '预览文件';
  }
  if (runButton) {
    runButton.disabled = state.importing || !hasData || !hasPreview;
    runButton.textContent = state.importing ? '处理中' : '执行导入';
  }
  if (closeButton) closeButton.disabled = state.importing;
  renderImportOutput();
};

const openImportModal = () => {
  state.importOpen = true;
  state.importError = '';
  renderImportModal();
  updateTopbar();
  requestAnimationFrame(() => $('download-template')?.focus());
};

const closeImportModal = () => {
  if (state.importing) return;
  state.importOpen = false;
  renderImportModal();
  updateTopbar();
};

const readFileAsText = file => new Promise((resolveText, rejectText) => {
  const reader = new FileReader();
  reader.onload = () => resolveText(String(reader.result || ''));
  reader.onerror = () => rejectText(new Error('读取导入文件失败'));
  reader.readAsText(file, 'utf-8');
});

const selectImportFile = async file => {
  state.importData = null;
  state.importPreview = null;
  state.importResult = null;
  state.importError = '';
  state.importFileName = file?.name || '';
  renderImportModal();
  if (!file) return;
  try {
    const name = String(file.name || '');
    if (!name.toLowerCase().endsWith('.json')) {
      throw new Error('请选择 .json 格式的导入文件。');
    }
    if (file.size > maxImportBytes) {
      throw new Error(`导入文件不能超过 ${formatBytes(maxImportBytes)}。`);
    }
    const raw = await readFileAsText(file);
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('导入文件必须是 JSON 对象。');
    }
    state.importData = parsed;
    notice('导入文件已读取，请先预览');
  } catch (error) {
    state.importData = null;
    state.importError = error instanceof Error ? error.message : '导入文件解析失败';
    notice(state.importError);
  } finally {
    renderImportModal();
  }
};

const downloadImportTemplate = async () => {
  state.importing = true;
  state.importError = '';
  renderImportModal();
  updateTopbar();
  try {
    const response = await adminFetch('/api/admin/import-template');
    if (response.status === 401) {
      redirectToLogin();
      throw new Error('Session expired, please sign in again');
    }
    if (!response.ok) throw new Error(await readResponseError(response));
    const blob = await response.blob();
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = 'payloader-import-template.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
    notice('导入模板已下载');
  } catch (error) {
    state.importError = error instanceof Error ? error.message : '下载导入模板失败';
    notice(state.importError);
  } finally {
    state.importing = false;
    renderImportModal();
    updateTopbar();
  }
};

const previewImportData = async () => {
  if (!state.importData) {
    notice('请先选择 JSON 导入文件');
    return;
  }
  state.importing = true;
  state.importPreview = null;
  state.importResult = null;
  state.importError = '';
  renderImportModal();
  updateTopbar();
  try {
    state.importPreview = await api('/api/admin/import/preview', {
      method: 'POST',
      body: JSON.stringify(state.importData),
    });
    notice('导入预览已生成');
  } catch (error) {
    state.importError = error instanceof Error ? error.message : '导入预览失败';
    notice(state.importError);
  } finally {
    state.importing = false;
    renderImportModal();
    updateTopbar();
  }
};

const runImportData = async () => {
  if (!state.importData || !state.importPreview) {
    notice('请先预览导入文件');
    return;
  }
  if (!(await confirmDiscard())) return;
  const modeText = importModeLabel(state.importMode);
  if (!(await requestConfirm({
    title: '确认导入',
    messageHtml: `确认按「${escapeHtml(modeText)}」导入 <strong>${escapeHtml(state.importFileName)}</strong>？导入后后台数据会刷新，未保存修改会丢失。`,
    confirmLabel: '执行导入',
    danger: true,
    requireText: 'IMPORT',
  }))) return;
  state.importing = true;
  state.importResult = null;
  state.importError = '';
  renderImportModal();
  updateTopbar();
  try {
    const result = await api('/api/admin/import', {
      method: 'POST',
      body: JSON.stringify({ mode: state.importMode, data: state.importData }),
    });
    state.importResult = result;
    state.selectedId = null;
    state.draft = null;
    state.activeSectionTitle = null;
    state.logoUploadMeta = null;
    state.dirty = false;
    await loadAll();
    notice('数据导入完成');
  } catch (error) {
    state.importError = error instanceof Error ? error.message : '数据导入失败';
    notice(state.importError);
  } finally {
    state.importing = false;
    renderImportModal();
    updateTopbar();
  }
};

const defaultSettings = () => ({
  siteTitle: { zh: 'PAYLOADER', en: 'PAYLOADER' },
  siteSubtitle: { zh: '渗透测试辅助平台', en: 'Pentest Assistance Platform' },
  browserTitle: { zh: 'Payloader - 渗透测试辅助平台', en: 'Payloader - Pentest Assistance Platform' },
  logoIcon: '⚡',
  logoUrl: '',
});

const defaultCommand = (target = 'tool') => {
  const label = { zh: '', en: '' };
  return {
    ...(target === 'payload' ? { title: label, requiresAdmin: false } : { name: label, examples: [] }),
    description: { zh: '', en: '' },
    command: '',
    platform: 'all',
    syntaxBreakdown: [],
  };
};

const defaultAttackChainStep = () => ({
  title: { zh: '', en: '' },
  description: { zh: '', en: '' },
  payload: '',
});

const defaultPayload = () => ({
  id: `payload-${crypto.randomUUID().slice(0, 8)}`,
  name: { zh: '', en: '' },
  description: { zh: '', en: '' },
  category: { zh: '', en: '' },
  subCategory: { zh: '', en: '' },
  tags: [],
  prerequisites: [],
  execution: [defaultCommand('payload')],
  opsecTips: [],
  wafBypass: [],
  attackChain: [],
  references: [],
  analysis: { zh: '', en: '' },
  tutorial: {
    overview: { zh: '', en: '' },
    vulnerability: { zh: '', en: '' },
    exploitation: { zh: '', en: '' },
    mitigation: { zh: '', en: '' },
    difficulty: 'beginner',
  },
});

const defaultTool = () => ({
  id: `tool-${crypto.randomUUID().slice(0, 8)}`,
  name: { zh: '', en: '' },
  description: { zh: '', en: '' },
  category: { zh: '', en: '' },
  commands: [defaultCommand('tool')],
  installation: { zh: '', en: '' },
  references: [],
});

const defaultNav = () => ({
  id: `nav-${crypto.randomUUID().slice(0, 8)}`,
  name: { zh: '', en: '' },
  kind: 'payloads',
  icon: '',
  children: [],
});

// ---- EXP 模块（v2.0.2）：漏洞利用条目全字段编辑 + 分类树管理 ----

const exploitVulnTypes = [
  'rce', 'sqli', 'deserialization', 'file-upload', 'auth-bypass', 'access-control',
  'ssrf', 'xxe', 'path-traversal', 'info-disclosure', 'memory-corruption', 'lpe', 'default-credentials',
];

const defaultExploit = () => ({
  id: '',
  name: '',
  description: '',
  vulnType: 'rce',
  affected: '',
  severity: 'high',
  publishedAt: '',
  vulnerabilityIds: [],
  exploitCode: [],
  prerequisites: '',
  references: [],
  tags: [],
  attribution: {},
});

const defaultExpNode = () => ({
  id: `expnode-${crypto.randomUUID().slice(0, 8)}`,
  name: { zh: '新建分类树', en: 'New category tree' },
  children: [],
});

const exploitVulnIdRow = (vid = {}, index) => `
  <div class="exp-row-card" data-section="vulnerabilityIds" data-index="${index}">
    <span class="exp-row-index">编号 ${index + 1}</span>
    <button class="exp-row-remove" type="button" data-action="remove-exp-vuln" data-index="${index}" title="删除此编号">✕ 删除</button>
    <div class="exp-row-grid">
      ${field(`exvuln-${index}-type`, '编号类型', vid.type || '', { list: 'exvuln-type-options' })}
      ${field(`exvuln-${index}-value`, '编号', vid.value || '')}
    </div>
  </div>
`;

const exploitCodeRow = (segment = {}, index) => `
  <div class="exp-row-card exp-row-code" data-section="exploitCode" data-index="${index}">
    <span class="exp-row-index">代码段 ${index + 1}</span>
    <button class="exp-row-remove" type="button" data-action="remove-exp-code" data-index="${index}" title="删除本段">✕ 删除</button>
    <div class="exp-row-grid exp-row-grid-code">
      ${field(`excode-${index}-title`, '段标题', segment.title || '')}
      ${field(`excode-${index}-language`, '语言', segment.language || '', { hint: '如 python / bash / http', list: 'excode-lang-options' })}
    </div>
    ${textarea(`excode-${index}-code`, '利用代码', segment.code || '', { wide: true, code: true })}
    ${textarea(`excode-${index}-desc`, '本段说明（可选）', segment.description || '', { wide: true })}
  </div>
`;

// 治理 M4：漏洞类型中文映射（后台表单与列表共用）
const exploitVulnTypeLabels = {
  rce: '远程代码执行', sqli: 'SQL 注入', deserialization: '反序列化', 'file-upload': '文件上传',
  'path-traversal': '路径遍历', 'auth-bypass': '认证绕过', 'access-control': '越权访问',
  'info-disclosure': '信息泄露', lpe: '本地提权', 'memory-corruption': '内存破坏', xss: '跨站脚本',
  xxe: 'XML 实体注入', ssrf: '服务端请求伪造', csrf: '跨站请求伪造', dos: '拒绝服务',
  ssti: '模板注入', 'default-credentials': '默认凭据', uncategorized: '未归类',
};
const exploitVulnTypeLabel = value => exploitVulnTypeLabels[value] || value;

// 分类挂载候选：展开 EXP 分类树的叶子（值=分类 id 路径，与策展管线 treePath 同形状；文案=名称路径）
const exploitTreePathOptions = () => {
  const options = [];
  const walk = (nodes, idPath, namePath) => {
    for (const node of nodes || []) {
      const nextIdPath = [...idPath, node.id];
      const nextNamePath = [...namePath, getText(node.name) || node.id];
      if (Array.isArray(node.children) && node.children.length) walk(node.children, nextIdPath, nextNamePath);
      else options.push({ id: nextIdPath.join('/'), name: `${nextNamePath.join(' / ')}（${node.id}）` });
    }
  };
  walk(state.exploitNavigation, [], []);
  return options;
};

const exploitSeverityLabels = { critical: '严重', high: '高危', medium: '中危', low: '低危', unknown: '未评级' };

// 条目概览行：编号/等级/日期/来源一览 + 前台详情直达（编辑表单之上的"详情卡"）
const exploitOverview = item => {
  const chips = [
    `<span class="exp-admin-sev exp-admin-sev-${escapeHtml(item.severity || 'medium')}">${exploitSeverityLabels[item.severity] || item.severity || '中危'}</span>`,
    ...(item.vulnerabilityIds || []).map(vid => `<span class="exp-admin-vid">${escapeHtml(vid.value)}</span>`),
    `<span class="exp-admin-meta">${escapeHtml(item.publishedAt || '日期未知')}</span>`,
    item.source && item.source !== 'curated' ? `<span class="exp-admin-src exp-admin-src-aggregated">聚合来源：${escapeHtml(item.source)}${item.sourceRef ? ` · ${escapeHtml(item.sourceRef)}` : ''}</span>` : '<span class="exp-admin-src exp-admin-src-curated">精选/手工层</span>',
  ];
  const frontendLink = item.id ? `<a class="exp-admin-frontend-link" href="/#/exploit/${encodeURIComponent(item.id)}" target="_blank" rel="noopener">在前台查看详情 ↗</a>` : '';
  return `<div class="exp-admin-overview"><div class="exp-admin-overview-chips">${chips.join('')}</div>${frontendLink}</div>`;
};

const renderExploitForm = () => {
  const item = clone(state.draft || selectedItem() || defaultExploit());
  const attribution = item.attribution || {};
  const originHint = item.source && item.source !== 'curated'
    ? `聚合层条目（来源 ${item.source}，上游主键 ${item.sourceRef || '无'}）：编辑后重跑聚合管线时，你的修改会被保留。`
    : '精选/手工层条目：经人工策展或后台手工创建。';
  const body = `
    ${datalist('exvuln-type-options', exploitVulnTypes.map(value => ({ id: value })))}
    ${datalist('excode-lang-options', [{ id: 'python' }, { id: 'bash' }, { id: 'http' }, { id: 'java' }, { id: 'c' }, { id: 'powershell' }, { id: 'metasploit' }])}
    ${datalist('exploit-treepath-options', exploitTreePathOptions())}
    ${exploitOverview(item)}
    ${section('基础信息', `结构化字段落库，前台与公开 API（AI 检索）共用这份数据。${originHint}`, `
      <div class="form-grid">
        ${field('exploit-id', 'ID', item.id, { readonly: true, hint: '新建时由系统生成 EXP-<ULID> 稳定标识。' })}
        ${field('exploit-name', '标题', item.name)}
        ${select('exploit-vulntype', '漏洞类型', item.vulnType || 'rce', exploitVulnTypes.map(value => ({ value, label: exploitVulnTypeLabels[value] ? `${exploitVulnTypeLabels[value]}（${value}）` : value })))}
        ${select('exploit-severity', '严重等级', item.severity || 'high', [
          { value: 'critical', label: '严重（critical）' },
          { value: 'high', label: '高危（high）' },
          { value: 'medium', label: '中危（medium）' },
          { value: 'low', label: '低危（low）' },
        ])}
        ${field('exploit-publishedat', '公开日期', item.publishedAt || '', { hint: '格式 YYYY 或 YYYY-MM-DD，不确定到日就写到月/年。' })}
        ${field('exploit-affected', '影响产品/组件与版本范围', item.affected || '')}
        ${textarea('exploit-desc', '漏洞描述', item.description || '', { wide: true })}
        ${textarea('exploit-prerequisites', '利用条件与前置说明', item.prerequisites || '', { wide: true })}
        ${field('exploit-tags', '标签', (item.tags || []).join(', '), { hint: '用逗号分隔，4-8 个为宜。' })}
        ${field('exploit-treepath', '分类挂载', item.treePath || '', { hint: '从 EXP 分类树选择叶子位置（分类树在本模块“分类树”分区维护）；留空表示未挂载。', list: 'exploit-treepath-options' })}
      </div>
    `)}
    ${section('漏洞编号', '多编号并存（CVE / CNVD / EDB-ID / GHSA…），支持按编号直达详情。', `
      <div class="collection">${(item.vulnerabilityIds || []).map(exploitVulnIdRow).join('') || '<div class="empty">还没有漏洞编号，点击“添加编号”创建一条。</div>'}</div>
    `, '<button class="btn" type="button" data-action="add-exp-vuln">添加编号</button>')}
    ${section('利用代码', '多段呈现，每段标注语言；教学导向，不写武器化增强。', `
      <div class="collection">${(item.exploitCode || []).map(exploitCodeRow).join('') || '<div class="empty">还没有利用代码，点击“添加代码段”创建一段。</div>'}</div>
    `, '<button class="btn" type="button" data-action="add-exp-code">添加代码段</button>')}
    ${section('参考与出处', '来源/作者/许可证允许留空，缺失是正常状态；参考链接建议 ≥2 条。', `
      <div class="form-grid">
        ${field('exploit-attr-source', '来源', attribution.source || '', { hint: '如公开 PoC 仓库名 / NVD。' })}
        ${field('exploit-attr-author', '原作者', attribution.author || '')}
        ${field('exploit-attr-license', '许可证', attribution.license || '')}
        ${textarea('exploit-references', '参考链接（每行一条）', joinPlainLines(item.references), { wide: true })}
      </div>
    `)}
    <div class="form-actions">
      ${item.enabled === false ? '<button class="btn" type="button" data-action="restore-exploit">恢复显示（当前已隐藏）</button>' : ''}
      <button class="btn primary" type="submit">保存 EXP</button>
      <button class="btn" type="button" id="cancel-item">取消修改</button>
    </div>
  `;
  $('editor-form').innerHTML = body;
};

const collectExploit = () => ({
  id: $('exploit-id')?.value.trim() || '',
  name: $('exploit-name')?.value.trim() || '',
  description: $('exploit-desc')?.value.trim() || '',
  vulnType: $('exploit-vulntype')?.value || 'rce',
  affected: $('exploit-affected')?.value.trim() || '',
  severity: $('exploit-severity')?.value || 'high',
  publishedAt: $('exploit-publishedat')?.value.trim() || '',
  vulnerabilityIds: [...document.querySelectorAll('.exp-row-card[data-section="vulnerabilityIds"]')].map(row => ({
    type: $(`exvuln-${row.dataset.index}-type`)?.value.trim() || '',
    value: $(`exvuln-${row.dataset.index}-value`)?.value.trim() || '',
  })).filter(vid => vid.type && vid.value),
  exploitCode: [...document.querySelectorAll('.exp-row-card[data-section="exploitCode"]')].map(row => {
    const segment = {
      title: $(`excode-${row.dataset.index}-title`)?.value.trim() || '',
      language: ($(`excode-${row.dataset.index}-language`)?.value.trim() || 'text').toLowerCase(),
      code: $(`excode-${row.dataset.index}-code`)?.value || '',
    };
    const description = $(`excode-${row.dataset.index}-desc`)?.value.trim() || '';
    if (description) segment.description = description;
    return segment;
  }).filter(segment => segment.code.trim()),
  prerequisites: $('exploit-prerequisites')?.value.trim() || '',
  references: splitLines($('exploit-references')?.value),
  tags: splitTags($('exploit-tags')?.value),
  treePath: $('exploit-treepath')?.value.trim() || '',
  // 聚合层来源标记透传：服务端 PUT 全量替换，丢失会让聚合条目泄漏进 public-data 快照
  ...(state.draft?.source ? { source: state.draft.source } : {}),
  ...(state.draft?.sourceRef ? { sourceRef: state.draft.sourceRef } : {}),
  attribution: {
    source: $('exploit-attr-source')?.value.trim() || '',
    author: $('exploit-attr-author')?.value.trim() || '',
    license: $('exploit-attr-license')?.value.trim() || '',
  },
});

const field = (id, label, value = '', options = {}) => `
  <label class="field ${options.wide ? 'wide' : ''}">
    <span>${label}</span>
    <input id="${id}" value="${escapeHtml(value)}" ${options.readonly ? 'readonly' : ''} ${options.list ? `list="${options.list}"` : ''} />
    ${options.hint ? `<small class="field-hint">${options.hint}</small>` : ''}
  </label>
`;

const textarea = (id, label, value = '', options = {}) => `
  <label class="field ${options.wide ? 'wide' : ''}">
    <span>${label}</span>
    <textarea id="${id}" class="${options.code ? 'code-input' : ''}">${escapeHtml(value)}</textarea>
    ${options.hint ? `<small class="field-hint">${options.hint}</small>` : ''}
  </label>
`;

const select = (id, label, value, choices, options = {}) => `
  <label class="field ${options.wide ? 'wide' : ''}">
    <span>${label}</span>
    <select id="${id}">
      ${choices.map(choice => `<option value="${choice.value}" ${choice.value === value ? 'selected' : ''}>${choice.label}</option>`).join('')}
    </select>
  </label>
`;

const datalist = (id, items) => `
  <datalist id="${id}">
    ${items.map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(getText(item.name) || item.id)}</option>`).join('')}
  </datalist>
`;

const section = (title, desc, body, actions = '') => {
  const index = state.editorSections.length;
  state.editorSections.push(title);
  const open = sectionOpenDefault(title, index) ? ' open' : '';
  const titleId = `section-title-${index}`;
  if (state.module !== 'settings') {
    return `
  <section class="form-section${open}" data-section-title="${escapeHtml(title)}">
    <button class="section-head" type="button" aria-expanded="${open ? 'true' : 'false'}">
      <div>
        <h3 id="${titleId}">${title}</h3>
        ${desc ? `<p>${desc}</p>` : ''}
      </div>
      <span class="section-edit-label">编辑</span>
    </button>
    <button class="section-backdrop" type="button" data-action="close-section" aria-label="关闭编辑弹窗"></button>
    <div class="section-modal" role="dialog" aria-modal="true" aria-labelledby="${titleId}">
      <div class="section-modal-head">
        <div>
          <h3>${title}</h3>
          ${desc ? `<p>${desc}</p>` : ''}
        </div>
        <button class="icon-btn au-modal-close" type="button" data-action="close-section" aria-label="关闭编辑弹窗" title="关闭">✕</button>
      </div>
      ${actions ? `<div class="section-actions">${actions}</div>` : ''}
      <div class="section-body">${body}</div>
      <div class="section-modal-foot">
        <span class="section-modal-hint">修改会先暂存在本页，点击「保存更改」提交到服务器。</span>
        <button class="btn" type="button" data-action="close-section">关闭</button>
        <button class="btn primary" type="button" data-action="save-section">保存更改</button>
      </div>
    </div>
  </section>
`;
  }
  return `
  <section class="form-section${open}" data-section-title="${escapeHtml(title)}">
    <button class="section-head" type="button" aria-expanded="${open ? 'true' : 'false'}">
      <div>
        <h3 id="${titleId}">${title}</h3>
        ${desc ? `<p>${desc}</p>` : ''}
      </div>
    </button>
    ${actions ? `<div class="section-actions">${actions}</div>` : ''}
    <div class="section-body">${body}</div>
  </section>
`;
};

const currentEditorTitle = () => {
  if (isSingletonModule()) return moduleConfig().title;
  const item = state.draft || selectedItem();
  return getText(item?.name) || item?.id || 'New item';
};

const currentEditorMeta = () => {
  if (isSingletonModule()) return '';
  const item = state.draft || selectedItem();
  return [item?.id, itemSummary(item)].filter(Boolean).join(' · ') || moduleConfig().title;
};

const updateEditorHead = () => {
  const moduleNode = $('editor-module-label');
  const titleNode = $('editor-title');
  const metaNode = $('editor-meta');
  if (moduleNode) moduleNode.textContent = moduleLabels[state.module] || moduleConfig().title;
  if (titleNode) titleNode.textContent = currentEditorTitle();
  if (metaNode) {
    metaNode.textContent = currentEditorMeta();
    metaNode.hidden = !metaNode.textContent;
  }
};

const updateMobileEditorHead = () => {
  const titleNode = $('mobile-item-title');
  const metaNode = $('mobile-item-meta');
  const backButton = $('mobile-back-list');
  if (titleNode) titleNode.textContent = currentEditorTitle();
  if (metaNode) {
    metaNode.textContent = currentEditorMeta();
    metaNode.hidden = !metaNode.textContent;
  }
  if (backButton) backButton.disabled = isSingletonModule();
};

const renderSectionTabs = () => {
  const node = $('section-tabs');
  if (!node) return;
  node.innerHTML = '';
};

const syncEditorChrome = () => {
  updateEditorHead();
  updateMobileEditorHead();
  renderSectionTabs();
};

const closeActiveSection = () => {
  for (const sectionNode of document.querySelectorAll('.form-section.open')) {
    sectionNode.classList.remove('open');
    sectionNode.querySelector('.section-head')?.setAttribute('aria-expanded', 'false');
  }
  state.activeSectionTitle = null;
  renderSectionTabs();
};

const openSection = sectionNode => {
  if (!sectionNode) return;
  for (const other of document.querySelectorAll('.form-section.open')) {
    if (other === sectionNode) continue;
    other.classList.remove('open');
    other.querySelector('.section-head')?.setAttribute('aria-expanded', 'false');
  }
  sectionNode.classList.add('open');
  sectionNode.querySelector('.section-head')?.setAttribute('aria-expanded', 'true');
  state.activeSectionTitle = sectionNode.dataset.sectionTitle || null;
  renderSectionTabs();
  requestAnimationFrame(() => {
    sectionNode.querySelector('.section-modal input:not([readonly]), .section-modal textarea, .section-modal select')?.focus?.();
  });
};

const focusSection = index => {
  const sections = [...document.querySelectorAll('.form-section')];
  const sectionNode = sections[index];
  if (!sectionNode) return;
  if (state.module !== 'settings') {
    openSection(sectionNode);
    return;
  }
  const compact = window.matchMedia('(max-width: 860px)').matches;
  if (compact) {
    for (const other of sections) {
      if (other !== sectionNode) {
        other.classList.remove('open');
        other.querySelector('.section-head')?.setAttribute('aria-expanded', 'false');
        state.sectionState[sectionKey(other.dataset.sectionTitle || '')] = false;
      }
    }
  }
  sectionNode.classList.add('open');
  sectionNode.querySelector('.section-head')?.setAttribute('aria-expanded', 'true');
  state.sectionState[sectionKey(sectionNode.dataset.sectionTitle || '')] = true;
  renderSectionTabs();
  sectionNode.scrollIntoView({ block: 'start', behavior: 'smooth' });
};

const textFields = (prefix, label, value, wide = false) => {
  const current = text(value);
  return `
    ${field(`${prefix}-zh`, `${label}（中文）`, current.zh, { wide })}
    ${field(`${prefix}-en`, `${label}（英文）`, current.en, { wide })}
  `;
};

const syntaxChoices = [
  'command',
  'parameter',
  'value',
  'operator',
  'variable',
  'header',
  'technique',
  'format',
  'function',
  'keyword',
  'encoding',
  'method',
  'domain',
  'tag',
  'path',
  'json',
  'concept',
  'char',
  'tool-mode',
];

const syntaxRows = (sectionName, commandIndex, syntax = []) => {
  if (!syntax.length) {
    return '<div class="empty compact">还没有语法解析项。</div>';
  }
  return syntax.map((part, partIndex) => {
    const explanation = text(part.explanation);
    return `
      <div class="mini-row syntax-row" data-section="${sectionName}" data-command-index="${commandIndex}" data-index="${partIndex}">
        ${field(`${sectionName}-${commandIndex}-syntax-${partIndex}-part`, '命令片段', part.part || '')}
        ${select(`${sectionName}-${commandIndex}-syntax-${partIndex}-type`, '类型', part.type || 'parameter', syntaxChoices.map(value => ({ value, label: value })))}
        ${textarea(`${sectionName}-${commandIndex}-syntax-${partIndex}-explain-zh`, '解释（中文）', explanation.zh, { wide: true })}
        ${textarea(`${sectionName}-${commandIndex}-syntax-${partIndex}-explain-en`, '解释（英文）', explanation.en, { wide: true })}
        <div class="mini-row-actions">
          <button class="icon-btn" type="button" data-action="move-syntax" data-section="${sectionName}" data-command-index="${commandIndex}" data-index="${partIndex}" data-direction="up">↑</button>
          <button class="icon-btn" type="button" data-action="move-syntax" data-section="${sectionName}" data-command-index="${commandIndex}" data-index="${partIndex}" data-direction="down">↓</button>
          <button class="icon-btn danger" type="button" data-action="remove-syntax" data-section="${sectionName}" data-command-index="${commandIndex}" data-index="${partIndex}">删除</button>
        </div>
      </div>
    `;
  }).join('');
};

const exampleRows = (sectionName, commandIndex, examples = []) => {
  if (!examples.length) {
    return '<div class="empty compact">还没有示例说明。</div>';
  }
  return examples.map((example, exampleIndex) => {
    const current = text(example);
    return `
      <div class="mini-row example-row" data-section="${sectionName}" data-command-index="${commandIndex}" data-index="${exampleIndex}">
        ${textarea(`${sectionName}-${commandIndex}-example-${exampleIndex}-zh`, '示例（中文）', current.zh, { wide: true })}
        ${textarea(`${sectionName}-${commandIndex}-example-${exampleIndex}-en`, '示例（英文）', current.en, { wide: true })}
        <div class="mini-row-actions">
          <button class="icon-btn" type="button" data-action="move-example" data-section="${sectionName}" data-command-index="${commandIndex}" data-index="${exampleIndex}" data-direction="up">↑</button>
          <button class="icon-btn" type="button" data-action="move-example" data-section="${sectionName}" data-command-index="${commandIndex}" data-index="${exampleIndex}" data-direction="down">↓</button>
          <button class="icon-btn danger" type="button" data-action="remove-example" data-section="${sectionName}" data-command-index="${commandIndex}" data-index="${exampleIndex}">删除</button>
        </div>
      </div>
    `;
  }).join('');
};

const commandRows = (sectionName, commands = [], target = 'tool') => {
  if (!commands.length) {
    return '<div class="empty">还没有命令，点击“添加命令”创建一条。</div>';
  }
  return commands.map((command, index) => {
    const name = text(target === 'payload' ? command.title : command.name);
    const desc = text(command.description);
    const showAdmin = target === 'payload';
    const showExamples = target === 'tool';
    return `
      <div class="collection-row">
        <div class="row-head">
          <strong>命令 ${index + 1}</strong>
          <div class="row-actions">
            <button class="icon-btn" type="button" data-action="move-command" data-section="${sectionName}" data-index="${index}" data-direction="up">↑</button>
            <button class="icon-btn" type="button" data-action="move-command" data-section="${sectionName}" data-index="${index}" data-direction="down">↓</button>
            <button class="icon-btn danger" type="button" data-action="remove-command" data-section="${sectionName}" data-index="${index}">删除</button>
          </div>
        </div>
        <div class="form-grid command-row" data-section="${sectionName}" data-index="${index}">
          ${field(`${sectionName}-${index}-name-zh`, '命令名（中文）', name.zh)}
          ${field(`${sectionName}-${index}-name-en`, '命令名（英文）', name.en)}
          ${select(`${sectionName}-${index}-platform`, '平台', command.platform || 'all', [
            { value: 'all', label: '全部平台' },
            { value: 'windows', label: 'Windows' },
            { value: 'linux', label: 'Linux' },
          ])}
          ${showAdmin ? `
            <label class="field">
              <span>需要管理员权限</span>
              <select id="${sectionName}-${index}-admin">
                <option value="false" ${command.requiresAdmin ? '' : 'selected'}>否</option>
                <option value="true" ${command.requiresAdmin ? 'selected' : ''}>是</option>
              </select>
            </label>
          ` : ''}
          ${textarea(`${sectionName}-${index}-command`, '命令内容', command.command || '', { wide: true, code: true })}
          ${textarea(`${sectionName}-${index}-desc-zh`, '说明（中文）', desc.zh, { wide: true })}
          ${textarea(`${sectionName}-${index}-desc-en`, '说明（英文）', desc.en, { wide: true })}
        </div>
        <div class="sub-editor">
          <div class="sub-editor-head">
            <strong>语法解析</strong>
            <button class="btn small" type="button" data-action="add-syntax" data-section="${sectionName}" data-command-index="${index}">添加解析项</button>
          </div>
          <div class="mini-list">${syntaxRows(sectionName, index, command.syntaxBreakdown || [])}</div>
        </div>
        ${showExamples ? `
          <div class="sub-editor">
            <div class="sub-editor-head">
              <strong>示例说明</strong>
              <button class="btn small" type="button" data-action="add-example" data-section="${sectionName}" data-command-index="${index}">添加示例</button>
            </div>
            <div class="mini-list">${exampleRows(sectionName, index, command.examples || [])}</div>
          </div>
        ` : ''}
      </div>
    `;
  }).join('');
};

const collectSyntaxParts = (sectionName, commandIndex) => {
  const rows = [...document.querySelectorAll(`.syntax-row[data-section="${sectionName}"][data-command-index="${commandIndex}"]`)];
  return rows.map(row => {
    const index = row.dataset.index;
    const part = $(`${sectionName}-${commandIndex}-syntax-${index}-part`)?.value.trim() || '';
    return {
      part,
      type: $(`${sectionName}-${commandIndex}-syntax-${index}-type`)?.value || 'parameter',
      explanation: makeText(
        $(`${sectionName}-${commandIndex}-syntax-${index}-explain-zh`)?.value,
        $(`${sectionName}-${commandIndex}-syntax-${index}-explain-en`)?.value,
      ),
    };
  }).filter(item => item.part);
};

const collectExamples = (sectionName, commandIndex) => {
  const rows = [...document.querySelectorAll(`.example-row[data-section="${sectionName}"][data-command-index="${commandIndex}"]`)];
  return rows.map(row => {
    const index = row.dataset.index;
    return makeText(
      $(`${sectionName}-${commandIndex}-example-${index}-zh`)?.value,
      $(`${sectionName}-${commandIndex}-example-${index}-en`)?.value,
    );
  }).filter(item => item.zh || item.en);
};

const collectCommands = (sectionName, target = 'tool') => {
  const rows = [...document.querySelectorAll(`.command-row[data-section="${sectionName}"]`)];
  return rows.map(row => {
    const index = row.dataset.index;
    const command = $(`${sectionName}-${index}-command`)?.value.trim() || '';
    const item = {
      command,
      description: makeText($(`${sectionName}-${index}-desc-zh`)?.value, $(`${sectionName}-${index}-desc-en`)?.value),
      platform: $(`${sectionName}-${index}-platform`)?.value || 'all',
      syntaxBreakdown: collectSyntaxParts(sectionName, index),
    };
    const label = makeText($(`${sectionName}-${index}-name-zh`)?.value, $(`${sectionName}-${index}-name-en`)?.value);
    if (target === 'payload') {
      item.title = label;
      item.requiresAdmin = $(`${sectionName}-${index}-admin`)?.value === 'true';
    } else {
      item.name = label;
      item.examples = collectExamples(sectionName, index);
    }
    return item;
  }).filter(item => item.command);
};

const attackChainRows = (steps = []) => {
  if (!steps.length) {
    return '<div class="empty">还没有攻击链步骤，点击“添加步骤”创建一条。</div>';
  }
  return steps.map((step, index) => {
    const title = text(step.title);
    const description = text(step.description);
    return `
      <div class="collection-row attack-chain-row" data-index="${index}">
        <div class="row-head">
          <strong>步骤 ${index + 1}</strong>
          <div class="row-actions">
            <button class="icon-btn" type="button" data-action="move-chain-step" data-index="${index}" data-direction="up">↑</button>
            <button class="icon-btn" type="button" data-action="move-chain-step" data-index="${index}" data-direction="down">↓</button>
            <button class="icon-btn danger" type="button" data-action="remove-chain-step" data-index="${index}">删除</button>
          </div>
        </div>
        <div class="form-grid">
          ${field(`chain-${index}-title-zh`, '步骤标题（中文）', title.zh)}
          ${field(`chain-${index}-title-en`, '步骤标题（英文）', title.en)}
          ${textarea(`chain-${index}-desc-zh`, '步骤说明（中文）', description.zh, { wide: true })}
          ${textarea(`chain-${index}-desc-en`, '步骤说明（英文）', description.en, { wide: true })}
          ${textarea(`chain-${index}-payload`, '关联 Payload（可选）', step.payload || '', { wide: true, code: true })}
        </div>
      </div>
    `;
  }).join('');
};

const collectAttackChain = () => {
  const rows = [...document.querySelectorAll('.attack-chain-row')];
  return rows.map(row => {
    const index = row.dataset.index;
    const payload = $(`chain-${index}-payload`)?.value.trim() || '';
    return {
      title: makeText($(`chain-${index}-title-zh`)?.value, $(`chain-${index}-title-en`)?.value),
      description: makeText($(`chain-${index}-desc-zh`)?.value, $(`chain-${index}-desc-en`)?.value),
      ...(payload ? { payload } : {}),
    };
  }).filter(item => item.title.zh || item.title.en || item.description.zh || item.description.en || item.payload);
};

const renderLogoManager = item => {
  const logoUrl = sanitizeLogoUrl(item.logoUrl);
  const fallbackIcon = item.logoIcon || '⚡';
  return `
    <div class="logo-manager wide">
      <input id="logo-url" type="hidden" value="${escapeHtml(logoUrl)}" />
      <div class="logo-preview" aria-label="当前 Logo 预览">
        ${logoUrl
          ? `<img src="${escapeHtml(logoUrl)}" alt="当前 Logo 图片" />`
          : `<span class="logo-preview-fallback">${escapeHtml(fallbackIcon)}</span>`}
      </div>
      <div class="logo-upload-panel">
        <div class="logo-upload-copy">
          <strong>Logo 图片</strong>
        </div>
        <div class="logo-upload-actions">
          <label class="btn logo-file-btn" for="logo-upload">上传图片</label>
          <input id="logo-upload" type="file" accept="image/png,image/jpeg,image/webp" />
          <button class="btn danger-soft" type="button" data-action="remove-logo" ${logoUrl ? '' : 'disabled'}>移除图片</button>
        </div>
        <div class="logo-path">
          <span>站点引用路径（自动生成）</span>
          <code>${escapeHtml(logoUrl || '未上传图片')}</code>
        </div>
        ${renderLogoUploadMeta(logoUrl)}
      </div>
    </div>
  `;
};

const renderSettingsForm = () => {
  const item = clone(state.draft || state.settings || defaultSettings());
  const body = `
    ${section('前台品牌', '', `
      <div class="form-grid">
        ${textFields('site-title', '站点标题', item.siteTitle)}
        ${textFields('site-subtitle', '站点副标题', item.siteSubtitle)}
        ${renderLogoManager(item)}
      </div>
    `)}
    ${section('浏览器标题', '', `
      <div class="form-grid">
        ${textFields('browser-title', '浏览器标题', item.browserTitle)}
      </div>
    `)}
    ${section('功能模块', '部署给他人使用时，可关闭仅面向自己使用的解题功能。', `
      <div class="form-grid form-grid-single">
        <label class="settings-toggle">
          <input type="checkbox" id="ctf-enabled" ${item.ctfEnabled !== false ? 'checked' : ''}/>
          <span class="settings-toggle-body">
            <strong>CTF 解题模块</strong>
            <small>关闭后前台隐藏「CTF 解题」标签页，并停用题目请求代理与端口扫描接口。本机离线客户端不受影响。</small>
          </span>
        </label>
      </div>
    `)}
  `;
  $('editor-form').innerHTML = body;
};

const formatBuildDate = value => {
  if (!value) return '尚未生成';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
};

const formatVersionDate = (value, fallback = '尚未检查') => {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  const pad = part => String(part).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
};

// 引擎层错误按稳定 code 映射为中文操作引导（engine 的英文 message 不进 UI）
const engineErrorText = (error, fallback = '检查失败，请稍后重试。') => ({
  timeout: '请求 GitHub 超时（10 秒上限），通常是网络波动，请稍后重试。',
  'network-error': '暂时无法连接 GitHub，请检查服务器网络后重试。',
  'rate-limited': 'GitHub 请求频率受限，请稍后再检查。',
  'github-error': 'GitHub 返回了异常响应，请稍后重试。',
  'not-found': '仓库不存在或为私有仓库，请确认订阅地址。',
  'invalid-response': 'GitHub 返回的内容无法解析，请稍后重试。',
  'too-many-redirects': '仓库重定向次数过多，已停止跟随，请确认当前仓库地址。',
  'response-too-large': 'GitHub 响应超出大小上限，已中止下载。',
  interrupted: '上次检查被中断，请重新检查。',
  'check-failed': '请稍后重试。',
}[error?.code] || error?.message || fallback);

const versionStatePresentation = value => ({
  idle: ['neutral', '等待检查'],
  checking: ['checking', '正在检查'],
  'update-available': ['warning', '发现新版本'],
  'source-update-available': ['warning', '源码有更新'],
  'up-to-date': ['success', '已是最新版本'],
  'local-newer': ['success', '本地版本领先'],
  checked: ['neutral', '检查完成'],
  error: ['danger', '检查失败'],
}[value] || ['neutral', '状态未知']);

// 空值统一灰显（与有效值拉开层级）
const emptyValuePattern = /^(?:未发布|未获取|未记录|未知|尚未检查|尚未正式发布|无法比较|未返回|未计划|暂无来源|—)$/;
const dimWhenEmpty = text => emptyValuePattern.test(String(text).trim())
  ? `<span class="au-empty">${escapeHtml(text)}</span>`
  : escapeHtml(text);

const plainReleaseNote = value => String(value || '')
  .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
  .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
  .replace(/`([^`]+)`/g, '$1')
  .replace(/[*_~]/g, '')
  .replace(/\s+/g, ' ')
  .trim()
  .slice(0, 240);

const importantReleaseNoticePattern = /(?:SmartScreen|SHA[- ]?256|公证|校验(?:和)?|未签名|已签名|签名凭据|\bunsigned\b|\bsigned\b|\bsigning\b|\bsignature\b|\bnotari[sz](?:e[ds]?|ation)?\b|\bchecksum\b|\bverif(?:y|ied|ication)\b)/i;
const releaseNoteNavigationPattern = /^\[[^\]]+\]\([^)]+\)(?:\s*\|\s*\[[^\]]+\]\([^)]+\))*$/;

const summarizeReleaseNotes = value => {
  const headings = [];
  const items = [];
  const notices = [];
  for (const rawLine of String(value || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('|')) continue;
    if (/^#{1,6}\s+/.test(line)) {
      const heading = plainReleaseNote(line.replace(/^#{1,6}\s+/, ''));
      if (heading && !/^direct client downloads$/i.test(heading)) headings.push(heading);
      continue;
    }
    if (/^[-*+]\s+/.test(line)) {
      const item = plainReleaseNote(line.replace(/^[-*+]\s+/, ''));
      if (item) items.push(item);
      continue;
    }
    if (releaseNoteNavigationPattern.test(line)) continue;
    const notice = plainReleaseNote(line);
    if (notice && importantReleaseNoticePattern.test(notice)) notices.push(notice);
  }
  return {
    title: headings[0] || '正式版本发布',
    items: [...new Set(items)].slice(0, 6),
    notices: [...new Set(notices)].slice(0, 2),
  };
};

const safeProjectRoute = value => /^\/api\/r\/[A-Za-z0-9/_-]+$/.test(String(value || ''))
  ? String(value)
  : '/api/r/p';

const renderVersionUpdateCenter = () => {
  const status = state.versionStatus || {};
  const installed = status.installed || {};
  const stable = status.stable || {};
  const error = status.error || null;
  const [tone, label] = versionStatePresentation(state.versionChecking ? 'checking' : status.state);
  const checking = state.versionChecking || status.state === 'checking';
  const rateLimit = status.rateLimit || {};
  const projectRoute = safeProjectRoute(status.projectRoute);
  const stableVersion = !stable.developmentMetadata && stable.version ? `v${stable.version}` : '未发布';
  const installedVersion = installed.version ? `v${installed.version}` : '未知';
  const releaseNotes = summarizeReleaseNotes(stable.notes);
  // API 配额：仅在检查失败时随错误说明展示（正常态对管理员是噪音）
  // isFinite 防御：rateLimit 经 localStorage 持久化回读，类型无契约，NaN 会让数值展示失效
  const quotaRemaining = Number(rateLimit.remaining);
  const quotaLimit = Number(rateLimit.limit);
  const quota = rateLimit.remaining !== null && rateLimit.remaining !== undefined
    && Number.isFinite(quotaRemaining) && Number.isFinite(quotaLimit) && quotaLimit > 0
    ? { remaining: quotaRemaining, limit: quotaLimit }
    : null;
  const quotaText = quota ? `${quota.remaining} / ${quota.limit}` : '';
  const body = `
    <div class="version-update-shell">
      <section class="version-update-summary" data-tone="${escapeHtml(tone)}">
        <div>
          <h3>${escapeHtml(label)}</h3>
        </div>
        <div class="version-update-actions">
          <button class="btn primary" type="button" data-action="check-version" ${checking ? 'disabled' : ''}>
            ${checking ? '正在检查' : '立即检查'}
          </button>
          <a class="btn" href="${escapeHtml(projectRoute)}" target="_blank" rel="noopener">查看官方项目</a>
        </div>
      </section>

      <div class="version-update-grid">
        <section class="version-update-panel">
          <header>
            <span>当前部署</span>
            <strong>${escapeHtml(installedVersion)}</strong>
          </header>
          <dl>
            <div><dt>部署提交</dt><dd><code>${escapeHtml(installed.commitShort || '未记录')}</code></dd></div>
          </dl>
        </section>

        <section class="version-update-panel">
          <header>
            <span>官方最新版本</span>
            <strong>${escapeHtml(stableVersion)}</strong>
          </header>
          <dl>
            <div><dt>发布时间</dt><dd>${dimWhenEmpty(formatVersionDate(stable.publishedAt, '未发布'))}</dd></div>
          </dl>
        </section>
      </div>

      <section class="version-update-timeline">
        <div><span>本次检查</span><strong>${dimWhenEmpty(formatVersionDate(status.checkedAt, '—'))}</strong></div>
        <div><span>下次计划</span><strong>${dimWhenEmpty(formatVersionDate(status.nextCheckAt, '未计划'))}</strong></div>
      </section>

      ${error ? `
        <section class="version-update-error" role="status">
          <strong>${escapeHtml(engineErrorText(error, '版本检查失败'))}</strong>
          <span>${error.retryAt ? `预计恢复：${escapeHtml(formatVersionDate(error.retryAt))}` : '系统会保留上次成功结果。'}${quota ? ` GitHub API 剩余 ${quotaText}。` : ''}</span>
        </section>
      ` : ''}

      ${stable.notes && (releaseNotes.items.length || releaseNotes.notices.length) ? `
        <section class="version-update-notes">
          <header>
            <span>版本说明</span>
            <strong>${escapeHtml(releaseNotes.title)}</strong>
          </header>
          <ul class="version-update-note-list">
            ${releaseNotes.items.map(item => `<li>${escapeHtml(item)}</li>`).join('')}
          </ul>
          ${releaseNotes.notices.length ? `
            <div class="version-update-note-notices" role="note">
              ${releaseNotes.notices.map(notice => `<p>${escapeHtml(notice)}</p>`).join('')}
            </div>
          ` : ''}
        </section>
      ` : ''}
    </div>
  `;
  $('editor-form').innerHTML = body;
};

const formatLargeBytes = value => {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 MB';
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
};

const clientBuildLatest = () => state.clientBuildStatus?.latest || null;
const clientBuildActive = () => state.clientBuildStatus?.active || null;
const clientBuildStaleLatest = () => state.clientBuildStatus?.staleLatest || null;
const clientBuildFailed = () => {
  return state.clientBuildStatus?.lastFailure || null;
};
const clientBuildIsBuilding = () => Boolean(clientBuildActive()) || state.clientBuildGenerating;
const clientBuildCounts = () => clientBuildLatest()?.publicStats
  || state.clientBuildStatus?.publicStats
  || {
    payloads: state.payloads.length,
    tools: state.tools.length,
    navigation: state.navigation.filter(item => item.kind !== 'tools').length,
    toolNavigation: state.navigation.filter(item => item.kind === 'tools').length,
  };

const clientBuildItems = () => {
  const latest = clientBuildLatest();
  if (Array.isArray(state.clientBuildStatus?.items) && state.clientBuildStatus.items.length) return state.clientBuildStatus.items;
  if (Array.isArray(latest?.items) && latest.items.length) return latest.items;
  if (latest?.fileName) return [latest];
  return [];
};

const clientBuildTargets = () => Array.isArray(state.clientBuildStatus?.targets) ? state.clientBuildStatus.targets : [];

const ensureClientBuildSelectedTargets = () => {
  const targets = clientBuildTargets();
  if (state.clientBuildSelectedTargets instanceof Set) {
    for (const id of [...state.clientBuildSelectedTargets]) {
      if (!targets.some(target => target.id === id && target.supported)) {
        state.clientBuildSelectedTargets.delete(id);
      }
    }
  }
  if (!(state.clientBuildSelectedTargets instanceof Set) || !state.clientBuildSelectedTargets.size) {
    state.clientBuildSelectedTargets = new Set(
      targets.filter(target => target.supported && target.selectedByDefault).map(target => target.id)
    );
  }
  return state.clientBuildSelectedTargets;
};

const clientPlatformLabel = value => {
  if (value === 'windows') return 'Windows';
  if (value === 'linux') return 'Linux';
  if (value === 'macos') return 'macOS';
  return value || 'Client';
};

const signingLabel = configured => configured ? '已配置签名' : '未签名';

const clientTargetMeta = target => [
  target.cpuFamily,
  target.minOsVersion,
  target.installType || target.packageManager,
].filter(Boolean).join(' · ');

const renderClientTargetMatrix = (targets, selectedTargets, isBuilding) => {
  if (!targets.length) {
    return '<div class="client-build-empty">后端暂未返回目标矩阵。</div>';
  }
  return `
    <div class="client-target-matrix" aria-label="客户端生成目标矩阵">
      ${targets.map(target => {
        const checked = selectedTargets.has(target.id);
        const disabled = !target.supported || isBuilding;
        return `
          <label class="client-target-card ${target.supported ? '' : 'disabled'} ${checked ? 'selected' : ''}">
            <input
              type="checkbox"
              data-client-target="${escapeHtml(target.id)}"
              ${checked ? 'checked' : ''}
              ${disabled ? 'disabled' : ''}
            />
            <span>${escapeHtml(target.platformLabel || clientPlatformLabel(target.platform))}</span>
            <strong>${escapeHtml(target.archLabel || target.arch)} / ${escapeHtml(target.format)}</strong>
            ${clientTargetMeta(target) ? `<em>${escapeHtml(clientTargetMeta(target))}</em>` : ''}
            <small>${target.supported
              ? target.source === 'official-shell'
                ? `官方套件 ${escapeHtml(target.shellVersion || '')}`.trim()
                : '本机工具链'
              : escapeHtml(target.reason || '不可生成')}</small>
          </label>
        `;
      }).join('')}
    </div>
  `;
};

const renderClientArtifacts = items => {
  if (!items.length) {
    return '<div class="client-build-empty">还没有可下载客户端。生成完成后会在这里列出每个平台和架构的文件。</div>';
  }
  return `
    <div class="client-artifact-table" role="table" aria-label="已生成客户端列表">
      <div class="client-artifact-row head" role="row">
        <span>平台</span>
        <span>架构 / 格式</span>
        <span>大小</span>
        <span>生成时间</span>
        <span>签名</span>
        <span>下载</span>
      </div>
      ${items.map(item => {
        const downloadUrl = item.fileName ? `/api/admin/client-builds/download/${encodeURIComponent(item.fileName)}` : '';
        return `
          <div class="client-artifact-row" role="row">
            <span>
              <strong>${escapeHtml(item.platformLabel || clientPlatformLabel(item.platform))}</strong>
              <small>${escapeHtml(item.fileName || '')}</small>
            </span>
            <span>${escapeHtml(item.archLabel || item.arch || '')}<small>${escapeHtml(item.format || '')}${item.buildSource === 'official-shell' ? ` · 官方套件 ${escapeHtml(item.shellVersion || '')}` : ' · 本机构建'}</small></span>
            <span>${formatLargeBytes(item.size)}</span>
            <span>${escapeHtml(formatBuildDate(item.generatedAt || item.finishedAt || item.startedAt))}</span>
            <span>${escapeHtml(signingLabel(item.codeSigningConfigured))}</span>
            <span>${downloadUrl ? `<a class="btn small success" href="${escapeHtml(downloadUrl)}">下载客户端</a>` : '不可用'}</span>
          </div>
          ${item.sha256 ? `<div class="client-artifact-hash"><span>SHA256</span><code>${escapeHtml(item.sha256)}</code></div>` : ''}
        `;
      }).join('')}
    </div>
  `;
};

const renderClientBuildFormV2 = () => {
  const latest = clientBuildLatest();
  const active = clientBuildActive();
  const failedBuild = clientBuildFailed();
  const items = clientBuildItems();
  const counts = clientBuildCounts();
  const isBuilding = clientBuildIsBuilding();
  const failed = Boolean(failedBuild);
  const environment = state.clientBuildStatus?.environment || {};
  const staleLatest = clientBuildStaleLatest();
  const targets = clientBuildTargets();
  const selectedTargets = ensureClientBuildSelectedTargets();
  const selectedCount = selectedTargets.size;
  const runtime = latest?.runtime || environment.runtime || 'electron-offline-client';
  const signingConfigured = Boolean(latest?.codeSigningConfigured || environment.codeSigningConfigured);
  const logs = [
    ...(Array.isArray(active?.logs) ? active.logs : []),
    ...(Array.isArray(failedBuild?.logs) ? failedBuild.logs : []),
    ...(Array.isArray(latest?.logs) ? latest.logs : []),
  ].filter(Boolean).slice(-5);
  const body = `
    <div class="client-build-shell">
      <section class="client-build-hero">
        <div>
          <span>Payloader Desktop Client</span>
          <h3>生成多平台客户端</h3>
        </div>
        <div class="client-build-actions">
          <button class="btn primary" type="button" data-action="generate-client-build" ${isBuilding || !selectedCount ? 'disabled' : ''}>
            ${isBuilding ? '正在生成' : `生成所选客户端${selectedCount ? `（${selectedCount}）` : ''}`}
          </button>
          <button class="btn" type="button" data-action="refresh-client-build" ${state.clientBuildLoading ? 'disabled' : ''}>刷新状态</button>
        </div>
      </section>

      <section class="client-build-grid" aria-label="客户端生成状态">
        <div class="client-build-card">
          <span>当前状态</span>
          <strong>${escapeHtml(active?.message || latest?.message || (staleLatest ? '旧客户端需要重新生成' : '尚未生成'))}</strong>
          <small>${active ? '执行中' : failed ? '上次失败' : staleLatest ? `需升级 contract ${escapeHtml(staleLatest.buildContractVersion || '-')}` : items.length ? `${items.length} 个制品` : '无制品'}</small>
        </div>
        <div class="client-build-card">
          <span>公开数据快照</span>
          <strong>${Number(counts.payloads || 0)} Payload / ${Number(counts.tools || 0)} 工具</strong>
          <small>${Number(counts.navigation || 0)} 个 Payload 导航根 · ${Number(counts.toolNavigation || 0)} 个工具导航根</small>
        </div>
        <div class="client-build-card">
          <span>签名状态</span>
          <strong>${signingLabel(signingConfigured)}</strong>
          <small>${signingConfigured ? '当前制品已标记签名' : '当前制品未签名'}</small>
        </div>
      </section>

      <section class="client-build-panel">
        <div class="client-build-panel-head">
          <div>
            <span>目标矩阵</span>
            <h3>选择要生成的客户端版本</h3>
          </div>
          <small>${escapeHtml(environment.platform || '')} / ${escapeHtml(environment.arch || '')}${environment.shellVersion ? ` · 官方套件 ${escapeHtml(environment.shellVersion)}` : ''}</small>
        </div>
        ${renderClientTargetMatrix(targets, selectedTargets, isBuilding)}
      </section>

      <section class="client-build-panel">
        <div class="client-build-panel-head">
          <div>
            <span>下载列表</span>
            <h3>已生成客户端</h3>
          </div>
          <small>${items.length} 个文件 · ${escapeHtml(runtime)}${staleLatest ? ' · 旧产物已隐藏' : ''}</small>
        </div>
        ${renderClientArtifacts(items)}
      </section>

      ${logs.length || failed ? `
        <section class="client-build-log">
          <h3>${failed ? '失败信息' : '构建日志'}</h3>
          <pre>${escapeHtml(logs.join('\n\n') || latest?.message || '生成失败')}</pre>
        </section>
      ` : ''}
    </div>
  `;
  $('editor-form').innerHTML = body;
};

// 密码框眼睛按钮（照搬登录页 login.html 的 SVG 与交互，data-eye 区分两态图标）
const passwordEyeButtons = inputId => `
  <button class="pw-toggle" type="button" data-action="toggle-password-visibility" data-target="${escapeHtml(inputId)}" aria-label="显示密码" aria-pressed="false" title="显示 / 隐藏密码">
    <svg data-eye="show" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
    <svg data-eye="hide" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" hidden><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/></svg>
  </button>
`;

const renderAccountForm = () => {
  const account = state.account || {};
  const forcedBanner = state.mustChangePassword ? `
      <section class="account-security-alert">
        <strong>必须修改默认密码后才能继续</strong>
        <span>当前管理员密码仍是系统默认密码，后台所有其他操作已被锁定。请在下方输入新密码并保存，保存成功后需重新登录。</span>
      </section>
    ` : '';
  // 直显表单（AW 批次）：不套 section() 弹窗折叠卡——改凭据是低频高危操作，
  // 直接摆在页面上填完点顶栏「保存」才是正常后台的心智模型。
  const body = `
    <div class="account-security-shell">
      ${forcedBanner}
      <section class="account-security-form" aria-labelledby="aw-account-title">
        <header class="aw-account-head">
          <div>
            <h3 id="aw-account-title">修改登录凭据</h3>
            <p>调整后点击右上角「保存」提交，取消可还原为当前值。</p>
          </div>
          <div class="aw-account-meta">
            <span>当前管理员</span>
            <strong>${escapeHtml(account.username || '')}</strong>
            <small>上次更新：${escapeHtml(account.updatedAt ? formatBuildDate(account.updatedAt) : '尚未记录')}</small>
          </div>
        </header>
        <div class="form-grid">
          <label class="field">
            <span>新用户名</span>
            <input
              id="account-username"
              autocomplete="username"
              maxlength="64"
              pattern="[A-Za-z0-9._\\-]{3,64}"
              spellcheck="false"
              value="${escapeHtml(account.username || '')}"
            />
            <small class="field-hint">3-64 位，只允许字母、数字、点、下划线和短横线；保持当前值即不修改。</small>
          </label>
          <label class="field">
            <span>当前密码</span>
            <span class="field-password-box">
              <input id="account-current-password" type="password" autocomplete="current-password" maxlength="128" />
              ${passwordEyeButtons('account-current-password')}
            </span>
            <small class="field-hint">验证身份必填。</small>
          </label>
          <label class="field">
            <span>新密码</span>
            <span class="field-password-box">
              <input id="account-new-password" type="password" autocomplete="new-password" maxlength="128" />
              ${passwordEyeButtons('account-new-password')}
            </span>
            <small class="field-hint">留空表示只改用户名；如填写，至少 10 位，并包含大小写字母、数字、符号中的三类。</small>
          </label>
          <label class="field field-full">
            <span>确认新密码</span>
            <span class="field-password-box">
              <input id="account-confirm-password" type="password" autocomplete="new-password" maxlength="128" />
              ${passwordEyeButtons('account-confirm-password')}
            </span>
            <small class="field-hint" id="pw-match-hint" data-state="">再次输入新密码，与新密码保持一致。</small>
          </label>
        </div>
        <p class="aw-account-note">保存后系统会清空所有后台会话，旧登录态立即失效，需使用新凭据重新登录。</p>
      </section>
    </div>
  `;
  $('editor-form').innerHTML = body;
};

// 确认新密码实时一致性提示（F-18）：匹配打勾 / 不匹配打叉，随输入即时刷新
const syncPasswordMatchHint = () => {
  const hint = $('pw-match-hint');
  if (!hint) return;
  const newValue = $('account-new-password')?.value || '';
  const confirmValue = $('account-confirm-password')?.value || '';
  if (!confirmValue) {
    hint.textContent = newValue ? '请再次输入新密码。' : '再次输入新密码，与新密码保持一致。';
    hint.dataset.state = '';
    return;
  }
  if (newValue === confirmValue) {
    hint.textContent = '✓ 两次输入一致';
    hint.dataset.state = 'ok';
  } else {
    hint.textContent = '✗ 两次输入不一致';
    hint.dataset.state = 'mismatch';
  }
};

const renderPayloadForm = () => {
  const item = clone(state.draft || selectedItem() || defaultPayload());
  item.tutorial = item.tutorial || defaultPayload().tutorial;
  const body = `
    ${section('基础信息', '决定列表、搜索和详情页头部展示。', `
      <div class="form-grid">
        ${field('payload-id', 'ID', item.id, { readonly: true, hint: '稳定标识，由系统生成，不可修改。' })}
        ${field('payload-tags', '标签', (item.tags || []).join(', '), { hint: '用逗号分隔。' })}
        ${textFields('payload-name', '名称', item.name)}
        ${textFields('payload-category', '分类', item.category)}
        ${textFields('payload-subcategory', '子分类', item.subCategory)}
        ${textarea('payload-desc-zh', '描述（中文）', text(item.description).zh, { wide: true })}
        ${textarea('payload-desc-en', '描述（英文）', text(item.description).en, { wide: true })}
      </div>
    `)}
    ${section('执行命令', '前台默认展示的主要命令。', `
      <div class="collection">${commandRows('execution', item.execution || [], 'payload')}</div>
    `, '<button class="btn" type="button" data-action="add-command" data-section="execution">添加命令</button>')}
    ${section('WAF 绕过', '按右上角 WAF 绕过模式维护同一漏洞类型下的可复制 Payload。', `
      <div class="collection-subtitle">WAF 绕过</div>
      <div class="collection">${commandRows('wafBypass', item.wafBypass || [], 'payload')}</div>
    `, `
      <button class="btn" type="button" data-action="add-command" data-section="wafBypass">添加 WAF 命令</button>
    `)}
    ${section('攻击链', '前台详情页的攻击链步骤。关联 Payload 可留空，也可以填写本步骤需要复制的载荷。', `
      <div class="collection">${attackChainRows(item.attackChain || [])}</div>
    `, '<button class="btn" type="button" data-action="add-chain-step">添加步骤</button>')}
    ${section('教程与分析', '这些内容展示在详情页的教程、分析和安全提示区域。', `
      <div class="form-grid">
        ${select('tutorial-difficulty', '难度', item.tutorial.difficulty || 'beginner', [
          { value: 'beginner', label: '入门' },
          { value: 'intermediate', label: '中级' },
          { value: 'advanced', label: '高级' },
          { value: 'expert', label: '专家' },
        ])}
        ${textarea('payload-analysis-zh', '结果分析（中文）', text(item.analysis).zh, { wide: true })}
        ${textarea('payload-analysis-en', '结果分析（英文）', text(item.analysis).en, { wide: true })}
        ${textarea('tutorial-overview-zh', '概述（中文）', text(item.tutorial.overview).zh, { wide: true })}
        ${textarea('tutorial-overview-en', '概述（英文）', text(item.tutorial.overview).en, { wide: true })}
        ${textarea('tutorial-vulnerability-zh', '漏洞原理（中文）', text(item.tutorial.vulnerability).zh, { wide: true })}
        ${textarea('tutorial-vulnerability-en', '漏洞原理（英文）', text(item.tutorial.vulnerability).en, { wide: true })}
        ${textarea('tutorial-exploitation-zh', '利用方法（中文）', text(item.tutorial.exploitation).zh, { wide: true })}
        ${textarea('tutorial-exploitation-en', '利用方法（英文）', text(item.tutorial.exploitation).en, { wide: true })}
        ${textarea('tutorial-mitigation-zh', '防护措施（中文）', text(item.tutorial.mitigation).zh, { wide: true })}
        ${textarea('tutorial-mitigation-en', '防护措施（英文）', text(item.tutorial.mitigation).en, { wide: true })}
      </div>
    `)}
    ${section('清单内容', '每行一条，适合维护前置条件、OpSec 提示和引用链接。', `
      <div class="form-grid">
        ${textarea('payload-prerequisites', '前置条件', joinTextLines(item.prerequisites), { wide: true })}
        ${textarea('payload-opsec', 'OpSec 提示', joinTextLines(item.opsecTips), { wide: true })}
        ${textarea('payload-references', '参考链接', joinPlainLines(item.references), { wide: true })}
      </div>
    `)}
    <div class="form-actions">
      <button class="btn primary" type="submit">保存 Payload</button>
      <button class="btn" type="button" id="cancel-item">取消修改</button>
    </div>
  `;
  $('editor-form').innerHTML = body;
};

// 默认外链（F-20）：系统锁定条目的引用链接只读展示；仅 http(s) 渲染为可点击外链，其余按纯文本展示
const safeExternalReferenceUrl = value => {
  const url = String(value || '').trim();
  return /^https?:\/\//i.test(url) ? url : '';
};

const lockedReferenceLinks = references => {
  const links = (Array.isArray(references) ? references : [])
    .map(reference => String(reference || '').trim())
    .filter(Boolean);
  if (!links.length) return '<span class="locked-record-empty">暂无外链</span>';
  return `<span class="locked-record-links">${links.map(link => {
    const safeUrl = safeExternalReferenceUrl(link);
    return safeUrl
      ? `<a href="${escapeHtml(safeUrl)}" target="_blank" rel="noopener">${escapeHtml(link)}</a>`
      : `<code>${escapeHtml(link)}</code>`;
  }).join('')}</span>`;
};

const renderToolForm = () => {
  const item = clone(state.draft || selectedItem() || defaultTool());
  const locked = Boolean(item.systemLocked);
  const body = `
    ${section('工具信息', '决定工具在前台列表和详情页中的展示。', `
      <div class="form-grid">
        ${field('tool-id', 'ID', item.id, { readonly: true, hint: '稳定标识，由系统生成，不可修改。' })}
        ${textFields('tool-name', '名称', item.name)}
        ${textFields('tool-category', '分类', item.category)}
        ${textarea('tool-desc-zh', '描述（中文）', text(item.description).zh, { wide: true })}
        ${textarea('tool-desc-en', '描述（英文）', text(item.description).en, { wide: true })}
        ${textarea('tool-install-zh', '安装方式（中文）', text(item.installation).zh, { wide: true })}
        ${textarea('tool-install-en', '安装方式（英文）', text(item.installation).en, { wide: true })}
      </div>
    `)}
    ${section('常用命令', '一条工具可以包含多条命令，顺序会影响前台展示。', `
      <div class="collection">${commandRows('commands', item.commands || [], 'tool')}</div>
    `, '<button class="btn" type="button" data-action="add-command" data-section="commands">添加命令</button>')}
    ${section('参考链接', '每行一个 URL。', `
      <div class="form-grid">
        ${textarea('tool-references', '参考链接', joinPlainLines(item.references), { wide: true })}
      </div>
    `)}
    ${locked ? `
      <div class="form-actions locked-links-block">
        <span class="locked-record-note">默认外链 · 只读</span>
        ${lockedReferenceLinks(item.references)}
        <small class="locked-record-hint">由客户端种子生成，请在数据维护中修改。</small>
      </div>
    ` : `
      <div class="form-actions">
        <button class="btn primary" type="submit">保存工具</button>
        <button class="btn" type="button" id="cancel-item">取消修改</button>
      </div>
    `}
  `;
  $('editor-form').innerHTML = body;
};

const navNodeRows = (nodes = [], pathPrefix = '') => {
  if (!nodes.length) return '<div class="empty">还没有子节点。</div>';
  return nodes.map((node, index) => {
    const path = pathPrefix ? `${pathPrefix}.${index}` : `${index}`;
    const name = text(node.name);
    return `
      <div class="collection-row nav-node" data-path="${path}">
        <div class="row-head">
          <strong>${getText(node.name) || node.id || '导航节点'}</strong>
          <div class="row-actions">
            <button class="icon-btn" type="button" data-action="add-nav-child" data-path="${path}">子节点</button>
            <button class="icon-btn" type="button" data-action="move-nav-node" data-path="${path}" data-direction="up">↑</button>
            <button class="icon-btn" type="button" data-action="move-nav-node" data-path="${path}" data-direction="down">↓</button>
            <button class="icon-btn danger" type="button" data-action="remove-nav-node" data-path="${path}">删除</button>
          </div>
        </div>
        <div class="form-grid nav-fields" data-path="${path}">
          ${field(`nav-${path}-id`, 'ID', node.id || '')}
          ${field(`nav-${path}-icon`, '图标', node.icon || '')}
          ${field(`nav-${path}-name-zh`, '名称（中文）', name.zh)}
          ${field(`nav-${path}-name-en`, '名称（英文）', name.en)}
          ${field(`nav-${path}-payload`, '绑定 Payload ID', node.payloadId || '', { list: 'payload-id-options' })}
          ${field(`nav-${path}-tool`, '绑定工具 ID', node.toolId || '', { list: 'tool-id-options' })}
        </div>
        <div class="collection nested-nav">
          ${navNodeRows(node.children || [], path)}
        </div>
      </div>
    `;
  }).join('');
};

const renderNavigationForm = () => {
  const item = clone(state.draft || selectedItem() || defaultNav());
  const name = text(item.name);
  const body = `
    ${datalist('payload-id-options', state.payloads)}
    ${datalist('tool-id-options', state.tools)}
    ${section('根节点', '根节点控制一棵导航树，类型决定它显示在 Payload 还是工具命令页面。', `
      <div class="form-grid">
        ${field('nav-id', 'ID', item.id, { readonly: true, hint: '稳定标识，由系统生成，不可修改。' })}
        ${select('nav-kind', '导航类型', item.kind || 'payloads', [
          { value: 'payloads', label: 'Payload 导航' },
          { value: 'tools', label: '工具命令导航' },
        ])}
        ${field('nav-icon', '图标', item.icon || '')}
        ${field('nav-name-zh', '名称（中文）', name.zh)}
        ${field('nav-name-en', '名称（英文）', name.en)}
        ${field('nav-payload', '绑定 Payload ID', item.payloadId || '', { hint: '根节点通常不需要绑定。', list: 'payload-id-options' })}
        ${field('nav-tool', '绑定工具 ID', item.toolId || '', { hint: '根节点通常不需要绑定。', list: 'tool-id-options' })}
      </div>
    `)}
    ${section('子节点', '用按钮添加、删除和调整子节点，不需要手写树结构。', `
      <div class="collection nested-nav root-nav">
        ${navNodeRows(item.children || [])}
      </div>
    `, '<button class="btn" type="button" data-action="add-nav-root-child">添加子节点</button>')}
    <div class="form-actions">
      <button class="btn primary" type="submit">保存导航树</button>
      <button class="btn" type="button" id="cancel-item">取消修改</button>
    </div>
  `;
  $('editor-form').innerHTML = body;
};

// ---- EXP 分类树：三级（漏洞大类 → 漏洞类型 → 子类），叶子节点绑定 exploitId ----

const expNodeRows = (nodes = [], pathPrefix = '') => {
  if (!nodes.length) return '<div class="empty">还没有子节点。</div>';
  return nodes.map((node, index) => {
    const path = pathPrefix ? `${pathPrefix}.${index}` : `${index}`;
    const name = text(node.name);
    return `
      <div class="collection-row nav-node" data-path="${path}">
        <div class="row-head">
          <strong>${getText(node.name) || node.id || '分类节点'}</strong>
          <div class="row-actions">
            <button class="icon-btn" type="button" data-action="add-expnode-child" data-path="${path}">子节点</button>
            <button class="icon-btn" type="button" data-action="move-expnode-node" data-path="${path}" data-direction="up">↑</button>
            <button class="icon-btn" type="button" data-action="move-expnode-node" data-path="${path}" data-direction="down">↓</button>
            <button class="icon-btn danger" type="button" data-action="remove-expnode-node" data-path="${path}">删除</button>
          </div>
        </div>
        <div class="form-grid nav-fields" data-path="${path}">
          ${field(`expnode-${path}-id`, 'ID', node.id || '', { hint: '稳定英文 slug（小写连字符），深链与种子对齐依赖它。' })}
          ${field(`expnode-${path}-name-zh`, '名称（中文）', name.zh)}
          ${field(`expnode-${path}-name-en`, '名称（英文）', name.en)}
          ${field(`expnode-${path}-exploit`, '绑定 EXP ID', node.exploitId || '', { hint: '叶子节点填 EXP-…；分类节点留空。', list: 'exploit-id-options' })}
        </div>
        <div class="collection nested-nav">
          ${expNodeRows(node.children || [], path)}
        </div>
      </div>
    `;
  }).join('');
};

const renderExploitNavigationForm = () => {
  const item = clone(state.draft || selectedItem() || defaultExpNode());
  const name = text(item.name);
  // 树绑定候选只列精选/手工层（无 source 标记）：聚合层万级条目按漏洞类型检索发现，不进树绑定下拉
  const curatedExploits = state.exploits.filter(exploitItem => !exploitItem.source || exploitItem.source === 'curated');
  const body = `
    ${datalist('exploit-id-options', curatedExploits)}
    ${section('根节点', '每个根节点是一棵漏洞分类树，建议按漏洞大类（Web 应用 / 中间件 / 权限提升…）组织。', `
      <div class="form-grid">
        ${field('expnode-root-id', 'ID', item.id, { readonly: true, hint: '稳定标识，由系统生成，不可修改。' })}
        ${field('expnode-root-name-zh', '名称（中文）', name.zh)}
        ${field('expnode-root-name-en', '名称（英文）', name.en)}
        ${field('expnode-root-exploit', '绑定 EXP ID', item.exploitId || '', { hint: '根节点通常不需要绑定。', list: 'exploit-id-options' })}
      </div>
    `)}
    ${section('子节点', '用按钮添加、删除和调整分类层级，不需要手写树结构。', `
      <div class="collection nested-nav root-nav">
        ${expNodeRows(item.children || [])}
      </div>
    `, '<button class="btn" type="button" data-action="add-expnode-root-child">添加子节点</button>')}
    <div class="form-actions">
      <button class="btn primary" type="submit">保存 EXP 分类树</button>
      <button class="btn" type="button" id="cancel-item">取消修改</button>
    </div>
  `;
  $('editor-form').innerHTML = body;
};

const collectSettings = () => ({
  siteTitle: makeText($('site-title-zh')?.value, $('site-title-en')?.value),
  siteSubtitle: makeText($('site-subtitle-zh')?.value, $('site-subtitle-en')?.value),
  browserTitle: makeText($('browser-title-zh')?.value, $('browser-title-en')?.value),
  logoIcon: state.draft?.logoIcon || state.settings?.logoIcon || '⚡',
  logoUrl: sanitizeLogoUrl($('logo-url')?.value),
  ctfEnabled: $('ctf-enabled')?.checked !== false,
});

const collectPayload = () => ({
  id: $('payload-id')?.value.trim() || defaultPayload().id,
  name: makeText($('payload-name-zh')?.value, $('payload-name-en')?.value),
  description: makeText($('payload-desc-zh')?.value, $('payload-desc-en')?.value),
  category: makeText($('payload-category-zh')?.value, $('payload-category-en')?.value),
  subCategory: makeText($('payload-subcategory-zh')?.value, $('payload-subcategory-en')?.value),
  tags: splitTags($('payload-tags')?.value),
  prerequisites: toTextList($('payload-prerequisites')?.value),
  execution: collectCommands('execution', 'payload'),
  wafBypass: collectCommands('wafBypass', 'payload'),
  attackChain: collectAttackChain(),
  analysis: makeText($('payload-analysis-zh')?.value, $('payload-analysis-en')?.value),
  opsecTips: toTextList($('payload-opsec')?.value),
  references: splitLines($('payload-references')?.value),
  tutorial: {
    overview: makeText($('tutorial-overview-zh')?.value, $('tutorial-overview-en')?.value),
    vulnerability: makeText($('tutorial-vulnerability-zh')?.value, $('tutorial-vulnerability-en')?.value),
    exploitation: makeText($('tutorial-exploitation-zh')?.value, $('tutorial-exploitation-en')?.value),
    mitigation: makeText($('tutorial-mitigation-zh')?.value, $('tutorial-mitigation-en')?.value),
    difficulty: $('tutorial-difficulty')?.value || 'beginner',
  },
});

const collectTool = () => ({
  id: $('tool-id')?.value.trim() || defaultTool().id,
  name: makeText($('tool-name-zh')?.value, $('tool-name-en')?.value),
  description: makeText($('tool-desc-zh')?.value, $('tool-desc-en')?.value),
  category: makeText($('tool-category-zh')?.value, $('tool-category-en')?.value),
  installation: makeText($('tool-install-zh')?.value, $('tool-install-en')?.value),
  commands: collectCommands('commands', 'tool'),
  references: splitLines($('tool-references')?.value),
});

const navPathParts = path => String(path || '').split('.').filter(Boolean).map(Number);
const getNavListAtPath = (item, path, parent = false) => {
  const parts = navPathParts(path);
  const targetParts = parent ? parts.slice(0, -1) : parts;
  let list = item.children || (item.children = []);
  for (const index of targetParts) {
    const node = list[index];
    if (!node) return [];
    list = node.children || (node.children = []);
  }
  return list;
};

const collectNavNode = path => {
  const node = {
    id: $(`nav-${path}-id`)?.value.trim() || `nav-${crypto.randomUUID().slice(0, 8)}`,
    name: makeText($(`nav-${path}-name-zh`)?.value, $(`nav-${path}-name-en`)?.value),
  };
  const icon = $(`nav-${path}-icon`)?.value.trim();
  const payloadId = $(`nav-${path}-payload`)?.value.trim();
  const toolId = $(`nav-${path}-tool`)?.value.trim();
  if (icon) node.icon = icon;
  if (payloadId) node.payloadId = payloadId;
  if (toolId) node.toolId = toolId;
  const card = document.querySelector(`.nav-node[data-path="${CSS.escape(path)}"]`);
  const childCards = [...(card?.querySelectorAll(':scope > .nested-nav > .nav-node') || [])];
  const children = childCards.map(child => collectNavNode(child.dataset.path));
  if (children.length) node.children = children;
  return node;
};

const collectNavigation = () => {
  const item = {
    id: $('nav-id')?.value.trim() || defaultNav().id,
    kind: $('nav-kind')?.value === 'tools' ? 'tools' : 'payloads',
    name: makeText($('nav-name-zh')?.value, $('nav-name-en')?.value),
  };
  const icon = $('nav-icon')?.value.trim();
  const payloadId = $('nav-payload')?.value.trim();
  const toolId = $('nav-tool')?.value.trim();
  if (icon) item.icon = icon;
  if (payloadId) item.payloadId = payloadId;
  if (toolId) item.toolId = toolId;
  const rootChildren = [...document.querySelectorAll('.root-nav > .nav-node')].map(node => collectNavNode(node.dataset.path));
  if (rootChildren.length) item.children = rootChildren;
  return item;
};

const collectExpNode = path => {
  const node = {
    id: $(`expnode-${path}-id`)?.value.trim() || `expnode-${crypto.randomUUID().slice(0, 8)}`,
    name: makeText($(`expnode-${path}-name-zh`)?.value, $(`expnode-${path}-name-en`)?.value),
  };
  const exploitId = $(`expnode-${path}-exploit`)?.value.trim();
  if (exploitId) node.exploitId = exploitId;
  const card = document.querySelector(`.nav-node[data-path="${CSS.escape(path)}"]`);
  const childCards = [...(card?.querySelectorAll(':scope > .nested-nav > .nav-node') || [])];
  const children = childCards.map(child => collectExpNode(child.dataset.path));
  if (children.length) node.children = children;
  return node;
};

const collectExploitNavigation = () => {
  const item = {
    id: $('expnode-root-id')?.value.trim() || defaultExpNode().id,
    name: makeText($('expnode-root-name-zh')?.value, $('expnode-root-name-en')?.value),
  };
  const exploitId = $('expnode-root-exploit')?.value.trim();
  if (exploitId) item.exploitId = exploitId;
  const rootChildren = [...document.querySelectorAll('.root-nav > .nav-node')].map(node => collectExpNode(node.dataset.path));
  if (rootChildren.length) item.children = rootChildren;
  return item;
};

const collectAccount = () => ({
  username: $('account-username')?.value.trim() || '',
  currentPassword: $('account-current-password')?.value || '',
  newPassword: $('account-new-password')?.value || '',
  confirmPassword: $('account-confirm-password')?.value || '',
});

const passwordClassCount = password => [
  /[a-z]/.test(password),
  /[A-Z]/.test(password),
  /\d/.test(password),
  /[^A-Za-z0-9]/.test(password),
].filter(Boolean).length;

const focusAccountField = id => {
  const node = $(id);
  node?.focus?.();
  node?.select?.();
};

const validateAccountInput = item => {
  if (!/^[A-Za-z0-9._-]{3,64}$/.test(item.username || '')) {
    notice('新用户名需为 3-64 位，只能包含字母、数字、点、下划线和短横线');
    focusAccountField('account-username');
    return false;
  }
  if (!item.currentPassword) {
    notice('请输入当前密码后再保存账号安全设置');
    focusAccountField('account-current-password');
    return false;
  }
  if (item.currentPassword.length > 128) {
    notice('当前密码长度不能超过 128 位');
    focusAccountField('account-current-password');
    return false;
  }
  if (item.newPassword || item.confirmPassword) {
    if (item.newPassword !== item.confirmPassword) {
      notice('两次输入的新密码不一致');
      focusAccountField('account-confirm-password');
      return false;
    }
    if (item.newPassword.length < 10 || item.newPassword.length > 128) {
      notice('新密码长度必须为 10-128 位');
      focusAccountField('account-new-password');
      return false;
    }
    if (passwordClassCount(item.newPassword) < 3) {
      notice('新密码至少需要包含大小写字母、数字、符号中的三类');
      focusAccountField('account-new-password');
      return false;
    }
    if (item.newPassword === item.currentPassword) {
      notice('新密码不能和当前密码相同');
      focusAccountField('account-new-password');
      return false;
    }
  }
  return true;
};

const hasBilingualText = value => Boolean(
  value
  && typeof value === 'object'
  && String(value.zh || '').trim()
  && String(value.en || '').trim()
);

const hasCompleteCommand = (entry, labelKey) => Boolean(
  String(entry?.command || '').trim()
  && hasBilingualText(entry?.[labelKey])
  && hasBilingualText(entry?.description)
);

const validationFailure = (message, fieldId) => {
  notice(message);
  const field = $(fieldId);
  field?.focus?.();
  field?.select?.();
  return false;
};

const validateContentInput = item => {
  if (state.module === 'payloads') {
    if (!hasBilingualText(item.name)) return validationFailure('请补全中英文名称', 'payload-name-zh');
    if (!hasBilingualText(item.description)) return validationFailure('请补全中英文描述', 'payload-desc-zh');
    if (!hasBilingualText(item.category)) return validationFailure('请补全中英文分类', 'payload-category-zh');
    if (!item.execution?.some(entry => hasCompleteCommand(entry, 'title'))) {
      return validationFailure('请至少添加一条完整的执行命令（含中英文标题、描述和命令）', 'payload-name-zh');
    }
    const tutorialFields = ['overview', 'vulnerability', 'exploitation', 'mitigation'];
    if (!tutorialFields.every(key => hasBilingualText(item.tutorial?.[key]))) {
      return validationFailure('请补全教程的中英文内容（概述、原理、利用方法和防护措施）', 'tutorial-overview-zh');
    }
    if (!hasBilingualText(item.analysis)) return validationFailure('请补全中英文结果分析', 'payload-analysis-zh');
    if (!item.prerequisites?.length) return validationFailure('请至少填写一项前置条件', 'payload-prerequisites');
    if (!item.opsecTips?.length) return validationFailure('请至少填写一项 OpSec 提示', 'payload-opsec');
    if (!item.references?.length) return validationFailure('请至少填写一个参考链接', 'payload-references');
  }

  if (state.module === 'tools') {
    if (!hasBilingualText(item.name)) return validationFailure('请补全中英文名称', 'tool-name-zh');
    if (!hasBilingualText(item.description)) return validationFailure('请补全中英文描述', 'tool-desc-zh');
    if (!hasBilingualText(item.category)) return validationFailure('请补全中英文分类', 'tool-category-zh');
    if (!hasBilingualText(item.installation)) return validationFailure('请补全中英文安装方式', 'tool-install-zh');
    if (!item.commands?.some(entry => hasCompleteCommand(entry, 'name'))) {
      return validationFailure('请至少添加一条完整的执行命令（含中英文名称、描述和命令）', 'tool-name-zh');
    }
    if (!item.references?.length) return validationFailure('请至少填写一个参考链接', 'tool-references');
  }

  if (state.module === 'exploits' && !isExpTreeSection()) {
    if (!item.name) return validationFailure('请填写 EXP 标题', 'exploit-name');
    if (!item.description) return validationFailure('请填写漏洞描述（机理 + 危害 + 触发路径）', 'exploit-desc');
    if (!item.affected) return validationFailure('请填写影响产品/组件与版本范围', 'exploit-affected');
    if (!item.vulnerabilityIds?.length) return validationFailure('请至少添加一个漏洞编号（CVE / CNVD / EDB-ID…）', 'exploit-name');
    if (!item.exploitCode?.some(segment => segment.code?.trim())) {
      return validationFailure('请至少添加一段利用代码', 'exploit-name');
    }
    if (!item.prerequisites) return validationFailure('请填写利用条件与前置说明', 'exploit-prerequisites');
    if (!item.references?.length) return validationFailure('请至少填写一个参考链接', 'exploit-references');
    if (!/^\d{4}(-\d{2})?(-\d{2})?$/.test(item.publishedAt || '')) {
      return validationFailure('公开日期格式应为 YYYY、YYYY-MM 或 YYYY-MM-DD', 'exploit-publishedat');
    }
    if (item.treePath) {
      const leafId = String(item.treePath).split('/').pop();
      const leafIds = new Set();
      const walkLeaves = nodes => (nodes || []).forEach(node => (
        Array.isArray(node.children) && node.children.length ? walkLeaves(node.children) : leafIds.add(node.id)
      ));
      walkLeaves(state.exploitNavigation);
      if (!leafIds.has(leafId)) {
        return validationFailure('分类挂载无效：分类树中不存在该叶子位置', 'exploit-treepath');
      }
    }
  }

  if (isExpTreeSection()) {
    const node = item;
    if (!hasBilingualText(node.name)) return validationFailure('请补全根节点中英文名称', 'expnode-root-name-zh');
    const flat = [];
    const walk = (children, depth) => {
      for (const child of children || []) {
        flat.push({ depth, hasExploit: Boolean(child.exploitId), name: child.name });
        walk(child.children, depth + 1);
      }
    };
    walk(node.children, 2);
    if (flat.length > 40) return validationFailure('分类树层级节点过多（>40），请拆分为多棵根树', 'expnode-root-name-zh');
    if (flat.some(entry => entry.depth > 4)) return validationFailure('分类层级不能超过三级（大类 → 类型 → 子类）', 'expnode-root-name-zh');
  }

  return true;
};

const collectCurrentForm = () => {
  if (state.module === 'settings') return collectSettings();
  if (state.module === 'account') return collectAccount();
  if (state.module === 'payloads') return collectPayload();
  if (state.module === 'tools') return collectTool();
  if (state.module === 'navigation') return collectNavigation();
  if (state.module === 'exploits' && !isExpTreeSection()) return collectExploit();
  if (isExpTreeSection()) return collectExploitNavigation();
  return null;
};

const renderEditor = () => {
  state.rendering = true;
  try {
    state.editorSections = [];
    if (state.module === 'settings') renderSettingsForm();
    if (state.module === 'payloads') renderPayloadForm();
    if (state.module === 'tools') renderToolForm();
    if (state.module === 'navigation') renderNavigationForm();
    if (state.module === 'exploits' && !isExpTreeSection()) renderExploitForm();
    if (isExpTreeSection()) renderExploitNavigationForm();
    if (state.module === 'clientBuilds') renderClientBuildFormV2();
    if (state.module === 'updates') renderVersionUpdateCenter();
    if (state.module === 'account') renderAccountForm();
    syncEditorChrome();
  } finally {
    state.rendering = false;
  }
};

const itemSummary = item => {
  if (!item) return '';
  if (state.module === 'payloads') return getText(item.category) || '未分类';
  if (state.module === 'tools') return `${getText(item.category) || '未分类'} · ${(item.commands || []).length} 条命令`;
  if (state.module === 'navigation') return `${item.kind === 'tools' ? '工具' : 'Payload'} · ${(item.children || []).length} 个子节点`;
  if (state.module === 'exploits' && !isExpTreeSection()) return `${exploitVulnTypeLabel(item.vulnType || 'uncategorized')} · ${({ critical: '严重', high: '高危', medium: '中危', low: '低危', unknown: '未评级' })[item.severity] || item.severity || '未评级'}`;
  if (state.module === 'exploitNavigation') return `分类树 · ${(item.children || []).length} 个子节点`;
  return '';
};

const itemMetaParts = item => {
  if (!item) return [];
  if (state.module === 'payloads') {
    return [
      getText(item.category) || '未分类',
      `${(item.execution || []).length} 条执行命令`,
      `${(item.tags || []).length} 个标签`,
    ];
  }
  if (state.module === 'tools') {
    return [
      getText(item.category) || '未分类',
      `${(item.commands || []).length} 条命令`,
      `${(item.references || []).length} 个链接`,
    ];
  }
  if (state.module === 'navigation') {
    return [
      item.kind === 'tools' ? '工具导航' : 'Payload 导航',
      `${(item.children || []).length} 个子节点`,
      item.payloadId || item.toolId ? '已绑定目标' : '分类节点',
    ];
  }
  if (state.module === 'exploits' && !isExpTreeSection()) {
    return [
      `${item.severity || 'medium'} · ${item.vulnType || 'uncategorized'}`,
      (item.vulnerabilityIds || []).map(vid => vid.value).join(' / ') || '无编号',
      item.publishedAt || '日期未知',
    ];
  }
  if (isExpTreeSection()) {
    return [
      'EXP 分类树',
      `${(item.children || []).length} 个子节点`,
      item.exploitId ? '已绑定目标' : '分类节点',
    ];
  }
  return [];
};

const itemGroupKey = item => {
  if (state.module === 'navigation') return item.kind === 'tools' ? '工具命令导航' : 'Payload 导航';
  if (isExpTreeSection()) return 'EXP 分类树';
  if (state.module === 'exploits' && !isExpTreeSection()) return item.vulnType || 'uncategorized';
  return getText(item.category) || '未分类';
};

const itemGroups = () => {
  const groups = new Map();
  for (const item of activeItems()) {
    const key = itemGroupKey(item);
    groups.set(key, (groups.get(key) || 0) + 1);
  }
  return [...groups.entries()];
};

const filteredItems = () => {
  const query = state.query.trim().toLowerCase();
  return activeItems().filter(item => {
    if (state.group && itemGroupKey(item) !== state.group) return false;
    if (!query) return true;
    const extra = state.module === 'exploits' && !isExpTreeSection()
      ? (item.vulnerabilityIds || []).map(vid => `${vid.type} ${vid.value}`).join(' ')
      : '';
    return [
      item.id,
      getText(item.name),
      getText(item.description),
      getText(item.category),
      item.kind,
      item.payloadId,
      item.toolId,
      item.vulnType,
      item.severity,
      item.affected,
      (item.tags || []).join(' '),
      extra,
    ].filter(Boolean).join(' ').toLowerCase().includes(query);
  });
};

const renderGroups = () => {
  const node = $('group-list');
  const selectNode = $('group-select');
  if (state.module === 'settings' || state.module === 'account') {
    node.innerHTML = '<div class="empty">站点设置不需要筛选。</div>';
    if (selectNode) {
      selectNode.innerHTML = '<option value="">全部分类</option>';
      selectNode.value = '';
    }
    return;
  }
  const groups = itemGroups();
  if (selectNode) {
    selectNode.innerHTML = [
      `<option value="">全部分类 (${activeItems().length})</option>`,
      ...groups.map(([name, count]) => `<option value="${escapeHtml(name)}">${escapeHtml(name)} (${count})</option>`),
    ].join('');
    selectNode.value = groups.some(([name]) => name === state.group) ? state.group : '';
  }
  node.innerHTML = groups.length ? groups.map(([name, count]) => `
    <button class="group-btn ${state.group === name ? 'active' : ''}" type="button" data-group="${escapeHtml(name)}">
      ${escapeHtml(name)} (${count})
    </button>
  `).join('') : '<div class="empty">暂无分组</div>';
};

const renderList = () => {
  const list = $('item-list');
  // 清空按钮随筛选态同步（renderList 是搜索/分组/清空/模块切换后必经的公共路径，
  // 放这里才能覆盖 search oninput 只走 renderList、不走完整 render 的入口）。
  const clearFilterButton = $('clear-filter');
  if (clearFilterButton) clearFilterButton.disabled = !state.query && !state.group;
  const items = filteredItems();
  const visibleItemLimit = state.visibleItemLimit;
  const firstPage = items.slice(0, visibleItemLimit);
  const selectedOutsidePage = items.find((item, index) => index >= visibleItemLimit && item.id === state.selectedId);
  const visibleItems = selectedOutsidePage ? [...firstPage, selectedOutsidePage] : firstPage;
  $('item-count').textContent = visibleItems.length < items.length
    ? `已加载 ${visibleItems.length} / 共 ${items.length} 条`
    : `共 ${items.length} 条`;
  const filterSummary = $('filter-summary');
  if (filterSummary) {
    filterSummary.textContent = state.group
      ? `${state.group} · 共 ${items.length} 条`
      : `全部分类 · 共 ${items.length} 条`;
  }
  if (state.module === 'settings' || state.module === 'account') {
    list.innerHTML = '<div class="empty">站点设置在右侧直接编辑。</div>';
    return;
  }
  if (!items.length) {
    list.innerHTML = '<div class="empty">没有匹配的数据</div>';
    return;
  }
  const rows = visibleItems.map(item => `
    <button class="item-row ${item.id === state.selectedId ? 'active' : ''}" type="button" data-id="${escapeHtml(item.id)}">
      <span class="item-main">
        <strong>${escapeHtml(getText(item.name) || item.id)}</strong>
        <small class="item-id">${escapeHtml(item.id)}</small>
        ${(state.module === 'exploits' && !isExpTreeSection()) && item.enabled === false ? '<small class="item-hidden-badge">已隐藏</small>' : ''}
      </span>
      <span class="item-meta">
        ${itemMetaParts(item).map(part => `<small>${escapeHtml(part)}</small>`).join('')}
      </span>
    </button>
  `).join('');
  const remaining = items.length - visibleItems.length;
  list.innerHTML = `${rows}${remaining > 0 ? `
    <button class="list-load-more" type="button" data-action="load-more-items">
      加载更多 <small>剩余 ${remaining} 条</small>
    </button>
  ` : ''}`;
};

const updateTopbar = () => {
  document.body.dataset.module = state.module;
  document.body.dataset.mobileView = currentMobileView();
  document.body.dataset.hasSelection = selectedItem() ? 'true' : 'false';
  document.body.dataset.hasDraft = state.draft ? 'true' : 'false';
  document.body.dataset.dirty = state.dirty ? 'true' : 'false';
  syncNavCollapse();
  $('module-title').textContent = moduleConfig().title;
  $('list-module-label').textContent = isExpTreeSection()
    ? 'EXP 分类树'
    : (moduleLabels[state.module] || moduleConfig().title);
  $('list-title').textContent = state.module === 'settings'
    ? '站点设置'
    : `${isExpTreeSection() ? 'EXP 分类树' : moduleConfig().title}列表`;
  const dataActions = !isSingletonModule();
  const singletonActions = state.module === 'settings' || state.module === 'account';
  const accountModule = state.module === 'account';
  const busy = state.loading || state.saving || state.importing || state.clientBuildGenerating || state.versionChecking;
  const lockedSelection = Boolean(selectedItem()?.systemLocked);
  $('save-current').disabled = busy || lockedSelection || (!singletonActions && !selectedItem() && !state.draft);
  $('cancel-current').disabled = busy || !state.dirty;
  $('new-item').disabled = busy || !dataActions;
  $('move-up').disabled = busy || lockedSelection || !dataActions || !selectedItem();
  $('move-down').disabled = busy || lockedSelection || !dataActions || !selectedItem();
  $('delete-item').disabled = busy || !dataActions || !selectedItem();
  $('open-import').disabled = busy;
  $('mobile-move-up').disabled = $('move-up').disabled;
  $('mobile-move-down').disabled = $('move-down').disabled;
  $('mobile-delete-item').disabled = $('delete-item').disabled;
  $('reset-module').disabled = busy || accountModule;
  $('reset-all').disabled = busy || accountModule;
  const clientBuildModule = state.module === 'clientBuilds';
  const updatesModule = state.module === 'updates';
  for (const buttonId of ['save-current', 'cancel-current', 'new-item', 'move-up', 'move-down', 'delete-item', 'open-import', 'reset-module', 'reset-all']) {
    $(buttonId)?.classList.toggle('hidden', clientBuildModule || updatesModule || (accountModule && !['save-current', 'cancel-current'].includes(buttonId)));
  }
  $('list-panel').classList.toggle('hidden', isSingletonModule());
  $('editor-head').classList.toggle('hidden', isSingletonModule());
  $('editor-mobile-head').classList.toggle('hidden', isSingletonModule());
  document.querySelector('.workspace').classList.toggle('settings-mode', isSingletonModule());
  $('mobile-view-switch')?.classList.toggle('hidden', isSingletonModule());
  for (const button of document.querySelectorAll('.view-btn')) {
    button.classList.toggle('active', button.dataset.view === currentMobileView());
  }
  updateSaveState();
};

const render = () => {
  let activeModuleButton = null;
  for (const button of document.querySelectorAll('.module-btn')) {
    const isActive = button.dataset.module === state.module;
    button.classList.toggle('active', isActive);
    if (isActive) activeModuleButton = button;
  }
  const moduleSelect = $('admin-module-select');
  if (moduleSelect && state.module !== 'custom') moduleSelect.value = state.module;
  // EXP 管理模块内分区条（条目管理 / 分类树）：仅 exploits 模块显示，随分区态高亮
  const expSectionBar = $('exp-section-bar');
  if (expSectionBar) {
    expSectionBar.classList.toggle('hidden', state.module !== 'exploits');
    for (const button of expSectionBar.querySelectorAll('.exp-section-btn')) {
      const isActive = button.dataset.section === state.expSection;
      button.classList.toggle('active', isActive);
      button.setAttribute('aria-pressed', isActive ? 'true' : 'false');
    }
  }
  const updateBadge = $('update-nav-badge');
  const updateAvailable = ['update-available', 'source-update-available'].includes(state.versionStatus?.state);
  if (updateBadge) updateBadge.classList.toggle('hidden', !updateAvailable);
  updateTopbar();
  renderGroups();
  renderList();
  renderEditor();
  renderImportModal();
  if (activeModuleButton && window.matchMedia('(max-width: 860px)').matches) {
    activeModuleButton.scrollIntoView({ block: 'nearest', inline: 'center' });
  }
};

let clientBuildPollTimer = null;

const scheduleClientBuildPoll = () => {
  clearTimeout(clientBuildPollTimer);
  if (!clientBuildActive()) return;
  clientBuildPollTimer = setTimeout(() => {
    loadClientBuildStatus({ quiet: true }).catch(error => notice(error.message || '刷新客户端生成状态失败'));
  }, 1600);
};

const loadClientBuildStatus = async (options = {}) => {
  state.clientBuildLoading = !options.quiet;
  updateTopbar();
  try {
    state.clientBuildStatus = await api('/api/admin/client-builds/status');
    if (state.module === 'clientBuilds') render();
    scheduleClientBuildPoll();
  } finally {
    state.clientBuildLoading = false;
    updateTopbar();
  }
};

const generateClientBuild = async () => {
  state.clientBuildGenerating = true;
  updateTopbar();
  try {
    const targets = [...ensureClientBuildSelectedTargets()];
    if (!targets.length) {
      notice('请至少选择一个当前环境可生成的客户端目标');
      return;
    }
    await api('/api/admin/client-builds/generate', { method: 'POST', body: JSON.stringify({ targets }) });
    notice('客户端生成任务已开始');
    await loadClientBuildStatus({ quiet: true });
  } finally {
    state.clientBuildGenerating = false;
    updateTopbar();
  }
};

const loadVersionStatus = async (options = {}) => {
  if (!options.quiet) state.versionChecking = true;
  updateTopbar();
  try {
    state.versionStatus = await api('/api/admin/version-status');
    if (state.module === 'updates') render();
    return state.versionStatus;
  } finally {
    if (!options.quiet) state.versionChecking = false;
    updateTopbar();
  }
};

const checkVersionNow = async () => {
  if (state.versionChecking) return;
  state.versionChecking = true;
  updateTopbar();
  if (state.module === 'updates') renderVersionUpdateCenter();
  try {
    state.versionStatus = await api('/api/admin/version-check', { method: 'POST' });
    notice(state.versionStatus.error ? '版本检查完成，但 GitHub 暂时不可用' : '版本状态已更新');
  } finally {
    state.versionChecking = false;
    if (state.module === 'updates') render();
    else updateTopbar();
  }
};

const loadAll = async () => {
  await loadSession();
  // 强制改密状态：其余管理端点会被服务端 403 拦截，只加载豁免的凭据信息并锁在账号安全模块
  if (state.mustChangePassword) {
    state.loading = true;
    updateTopbar();
    try {
      state.account = await api('/api/admin/credentials');
      state.module = 'account';
      state.draft = null;
      state.dirty = false;
      state.mobileView = defaultMobileView('account');
      render();
      notice('当前仍在使用默认管理员密码：请先修改密码，修改后需重新登录');
    } finally {
      state.loading = false;
      updateTopbar();
    }
    return;
  }
  state.loading = true;
  updateTopbar();
  try {
    const [settings, payloads, tools, navigation, exploits, exploitNavigation, clientBuildStatus, versionStatus, account] = await Promise.all([
      api('/api/admin/settings'),
      api('/api/admin/payloads'),
      api('/api/admin/tools'),
      api('/api/admin/navigation'),
      api('/api/admin/exploits'),
      api('/api/admin/exploit_navigation'),
      api('/api/admin/client-builds/status'),
      api('/api/admin/version-status'),
      api('/api/admin/credentials'),
    ]);
    state.settings = settings || defaultSettings();
    state.payloads = Array.isArray(payloads.items) ? payloads.items : [];
    state.tools = Array.isArray(tools.items) ? tools.items : [];
    state.navigation = Array.isArray(navigation.items) ? navigation.items : [];
    state.exploits = Array.isArray(exploits.items) ? exploits.items : [];
    state.exploitNavigation = Array.isArray(exploitNavigation.items) ? exploitNavigation.items : [];
    state.clientBuildStatus = clientBuildStatus;
    state.versionStatus = versionStatus;
    state.account = account;
    if (!isSingletonModule() && !selectedItem()) {
      state.selectedId = activeItems()[0]?.id || null;
    }
    state.draft = null;
    state.activeSectionTitle = null;
    state.logoUploadMeta = null;
    state.dirty = false;
    state.mobileView = defaultMobileView(state.module);
    render();
    scheduleClientBuildPoll();
  } finally {
    state.loading = false;
    updateTopbar();
  }
};

const saveCurrent = async () => {
  if (state.module === 'clientBuilds') return;
  const item = collectCurrentForm();
  if (state.module === 'account' && !validateAccountInput(item)) return;
  if (!validateContentInput(item)) return;
  state.saving = true;
  updateTopbar();
  try {
    if (state.module === 'account') {
      await api('/api/admin/credentials', { method: 'PUT', body: JSON.stringify(item) });
      sessionStorage.removeItem(adminTokenStorageKey);
      state.accessToken = '';
      notice('账号安全设置已保存，请重新登录');
      window.setTimeout(() => window.location.replace('/admin/login'), 600);
      return;
    }

    if (state.module === 'settings') {
      state.settings = await api('/api/admin/settings', { method: 'PUT', body: JSON.stringify(item) });
      state.draft = clone(state.settings);
      state.logoUploadMeta = null;
      state.dirty = false;
      render();
      notice('站点设置已保存');
      return;
    }

    const existing = selectedItem();
    const method = existing && existing.id === item.id ? 'PUT' : 'POST';
    const url = method === 'PUT' ? `${resourceApi()}/${encodeURIComponent(item.id)}` : resourceApi();
    const saved = await api(url, { method, body: JSON.stringify(item) });
    state.selectedId = saved.id;
    await loadAll();
    setMobileView('editor');
    notice('已保存');
  } finally {
    state.saving = false;
    updateTopbar();
  }
};

const newItem = async () => {
  if (!(await confirmDiscard())) return;
  if (state.module === 'payloads') state.draft = defaultPayload();
  if (state.module === 'tools') state.draft = defaultTool();
  if (state.module === 'navigation') state.draft = defaultNav();
  if (state.module === 'exploits' && !isExpTreeSection()) state.draft = defaultExploit();
  if (isExpTreeSection()) state.draft = defaultExpNode();
  state.selectedId = null;
  state.activeSectionTitle = null;
  state.logoUploadMeta = null;
  state.dirty = true;
  state.mobileView = 'editor';
  render();
};

const moveSelected = async direction => {
  if (!(await confirmDiscard())) return;
  const item = selectedItem();
  if (!item || state.module === 'settings') return;
  state.saving = true;
  updateTopbar();
  try {
    const data = await api(`${resourceApi()}/${encodeURIComponent(item.id)}/move`, {
      method: 'POST',
      body: JSON.stringify({ direction }),
    });
    state[resourceStateKey()] = Array.isArray(data.items) ? data.items : activeItems();
    render();
  } finally {
    state.saving = false;
    updateTopbar();
  }
};

const deleteSelected = async () => {
  if (!(await confirmDiscard())) return;
  const item = selectedItem();
  if (!item || state.module === 'settings') return;
  if (!(await requestConfirm({
    title: '删除当前记录',
    messageHtml: `确认删除 <strong>${escapeHtml(getText(item.name) || item.id)}</strong>？删除后不可恢复。`,
    confirmLabel: '删除',
    danger: true,
    requireText: item.id,
  }))) return;
  state.saving = true;
  updateTopbar();
  try {
    await api(`${resourceApi()}/${encodeURIComponent(item.id)}`, { method: 'DELETE' });
    state.selectedId = null;
    await loadAll();
    state.mobileView = defaultMobileView(state.module);
    notice('已删除');
  } finally {
    state.saving = false;
    updateTopbar();
  }
};

const resetCurrent = async target => {
  if (state.module === 'clientBuilds' || state.module === 'updates' || state.module === 'account' || state.saving) return;
  state.saving = true;
  updateTopbar();
  try {
    const impact = await api(`/api/admin/reset-impact?target=${encodeURIComponent(target)}`);
    if (!(await confirmDiscard())) return;

    if (!impact?.before || !impact?.seed || !impact?.delta || !Array.isArray(impact?.affected)) {
      throw new Error('无法读取完整的重置影响预览，请稍后重试');
    }

    const resetScopeLabels = {
      payloads: 'Payload',
      tools: '工具命令',
      navigation: 'Payload 导航节点',
      toolNavigation: '工具导航节点',
      settings: '站点设置',
      exploits: 'EXP 条目',
      exploitNavigation: 'EXP 分类树节点',
    };
    const impactLines = impact.affected.map(scope => {
      const before = Number(impact.before[scope] || 0);
      const seed = Number(impact.seed[scope] || 0);
      const delta = Number(impact.delta[scope] || 0);
      const signedDelta = delta > 0 ? `+${delta}` : String(delta);
      return `- ${resetScopeLabels[scope] || scope}：重置前 ${before} / 默认 ${seed} / 净变化 ${signedDelta}`;
    });
    const xeyeImpact = impact.integrations?.xeye;
    if (xeyeImpact?.affected) {
      const beforeLabel = xeyeImpact.before ? '当前已启用' : '当前已删除';
      const afterLabel = xeyeImpact.seed
        ? (xeyeImpact.before ? '重置后保持启用' : '重置后恢复')
        : '重置后关闭';
      impactLines.push(`- Xeye 平台入口：${beforeLabel} / ${afterLabel}`);
    }
    const isAll = target === 'all';
    const resetScope = isAll
      ? '这会把站点设置、Payload、工具命令和导航树全部重置为内置默认数据。'
      : `这会把当前模块「${moduleConfig().title}」重置为内置默认数据。`;
    const confirmed = await requestConfirm({
      title: isAll ? '重置全部数据' : '重置当前模块',
      messageHtml: [
        escapeHtml(resetScope),
        '<strong>重置影响预览：</strong>',
        `<ul class="confirm-modal-list">${impactLines.map(line => `<li>${escapeHtml(line)}</li>`).join('')}</ul>`,
        escapeHtml('系统会在写入默认数据前先创建数据库备份；重置成功后会显示备份文件位置。现有已保存数据会被覆盖，未保存修改也会丢失。'),
      ].join(''),
      confirmLabel: '确认重置',
      danger: true,
      requireText: isAll ? 'RESET ALL' : 'RESET',
    });
    if (!confirmed) return;

    const result = await api('/api/admin/reset-defaults', { method: 'POST', body: JSON.stringify({ target }) });
    state.selectedId = null;
    state.draft = null;
    state.activeSectionTitle = null;
    state.logoUploadMeta = null;
    await loadAll();
    const backupPath = typeof result?.backup?.path === 'string' ? result.backup.path.trim() : '';
    const backupFileName = typeof result?.backup?.fileName === 'string' ? result.backup.fileName.trim() : '';
    const backupLocation = backupPath || backupFileName;
    const resetMessage = isAll ? '已将全部后台数据重置为默认数据' : `已将 ${moduleConfig().title} 重置为默认数据`;
    notice(backupLocation ? `${resetMessage}；备份：${backupLocation}` : resetMessage);
  } finally {
    state.saving = false;
    updateTopbar();
  }
};

const cancelCurrentEdit = async () => {
  if (!state.dirty && !state.draft) return;
  if (!(await confirmDiscard())) return;
  if (state.module === 'account') {
    state.draft = null;
    state.activeSectionTitle = null;
    state.dirty = false;
    render();
    return;
  }
  state.draft = null;
  state.activeSectionTitle = null;
  state.logoUploadMeta = null;
  state.dirty = false;
  if (state.module !== 'settings' && !selectedItem()) {
    state.selectedId = activeItems()[0]?.id || null;
    state.mobileView = defaultMobileView(state.module);
  }
  render();
};

const mutateDraft = action => {
  state.draft = collectCurrentForm();
  action(state.draft);
  state.dirty = true;
  renderEditor();
  updateTopbar();
};

const readFileAsDataUrl = file => new Promise((resolveDataUrl, rejectDataUrl) => {
  const reader = new FileReader();
  reader.onload = () => resolveDataUrl(String(reader.result || ''));
  reader.onerror = () => rejectDataUrl(new Error('读取 Logo 图片失败'));
  reader.readAsDataURL(file);
});

const readLogoImageInfo = file => new Promise((resolveInfo, rejectInfo) => {
  const objectUrl = URL.createObjectURL(file);
  const image = new Image();
  image.onload = () => {
    const info = { width: image.naturalWidth, height: image.naturalHeight };
    URL.revokeObjectURL(objectUrl);
    resolveInfo(info);
  };
  image.onerror = () => {
    URL.revokeObjectURL(objectUrl);
    rejectInfo(new Error('无法读取 Logo 图片尺寸，请换一张有效图片'));
  };
  image.src = objectUrl;
});

const validateLogoFile = async file => {
  const ext = logoFileExtension(file);
  if (!acceptedLogoTypes.has(file.type) || !acceptedLogoExtensions.has(ext)) {
    notice('仅支持扩展名为 .png、.jpg、.jpeg、.webp 的图片文件');
    return null;
  }
  if (file.size > maxLogoBytes) {
    notice('Logo 图片不能超过 1 MB');
    return null;
  }
  const imageInfo = await readLogoImageInfo(file);
  if (
    imageInfo.width < 1 ||
    imageInfo.height < 1 ||
    imageInfo.width > maxLogoDimension ||
    imageInfo.height > maxLogoDimension
  ) {
    notice(`Logo 图片宽高不能超过 ${maxLogoDimension}px`);
    return null;
  }
  return imageInfo;
};

const updateLogoUrl = (logoUrl, uploadMeta = null) => {
  const safeLogoUrl = sanitizeLogoUrl(logoUrl);
  const input = $('logo-url');
  if (input) input.value = safeLogoUrl;
  state.logoUploadMeta = uploadMeta && safeLogoUrl ? { ...uploadMeta, logoUrl: safeLogoUrl } : null;
  state.draft = collectCurrentForm();
  state.dirty = true;
  renderEditor();
  updateTopbar();
};

const uploadLogoFile = async file => {
  if (!file) return;
  const imageInfo = await validateLogoFile(file);
  if (!imageInfo) return;
  state.saving = true;
  updateTopbar();
  try {
    const dataUrl = await readFileAsDataUrl(file);
    const result = await api('/api/admin/logo', {
      method: 'POST',
      body: JSON.stringify({ dataUrl, mimeType: file.type }),
    });
    const safeLogoUrl = sanitizeLogoUrl(result.logoUrl);
    if (!safeLogoUrl) throw new Error('后台返回的 Logo 路径不安全，已拒绝使用');
    updateLogoUrl(safeLogoUrl, {
      fileName: file.name,
      mimeType: result.mimeType || file.type,
      width: result.width || imageInfo.width,
      height: result.height || imageInfo.height,
      size: result.size || file.size,
    });
    notice('Logo 图片已上传，请保存站点设置');
  } finally {
    state.saving = false;
    updateTopbar();
  }
};

const swapArrayItem = (array, index, direction) => {
  const other = direction === 'up' ? index - 1 : index + 1;
  if (other < 0 || other >= array.length) return;
  [array[index], array[other]] = [array[other], array[index]];
};

const commandTarget = sectionName => sectionName === 'commands' ? 'tool' : 'payload';

const commandAt = (draft, sectionName, commandIndex) => {
  const list = draft[sectionName] = Array.isArray(draft[sectionName]) ? draft[sectionName] : [];
  const index = Number(commandIndex);
  if (!list[index]) {
    list[index] = defaultCommand(commandTarget(sectionName));
  }
  return list[index];
};

document.addEventListener('click', async event => {
  const button = event.target.closest('button');
  if (!button) return;

  if (button.dataset.action === 'toggle-admin-nav') {
    state.navCollapsed = !state.navCollapsed;
    localStorage.setItem('payloader-admin-nav-collapsed', state.navCollapsed ? '1' : '0');
    syncNavCollapse();
    return;
  }

  // 密码显示/隐藏切换（对齐登录页眼睛按钮的交互）：键盘激活不抢焦点，指针点击回焦输入框
  if (button.dataset.action === 'toggle-password-visibility') {
    const input = $(button.dataset.target);
    if (!input) return;
    const visible = input.type === 'password';
    input.type = visible ? 'text' : 'password';
    button.setAttribute('aria-pressed', String(visible));
    button.setAttribute('aria-label', visible ? '隐藏密码' : '显示密码');
    const showIcon = button.querySelector('[data-eye="show"]');
    const hideIcon = button.querySelector('[data-eye="hide"]');
    if (showIcon) showIcon.hidden = visible;
    if (hideIcon) hideIcon.hidden = !visible;
    if (event.detail > 0) input.focus();
    return;
  }

  if (button.dataset.action === 'check-version') {
    checkVersionNow().catch(error => notice(error.message || '版本检查失败'));
    return;
  }

  if (button.matches('.exp-section-btn')) {
    // EXP 管理模块内分区切换（条目管理 / 分类树）：切数据面，模块保持 exploits
    if (state.module !== 'exploits') return;
    const nextSection = button.dataset.section === 'tree' ? 'tree' : 'items';
    if (nextSection === state.expSection) return;
    if (!(await confirmDiscard())) return;
    state.expSection = nextSection;
    // 默认选中该分区第一项：避免树分区落进"空编辑器"无从下手
    state.selectedId = activeItems()[0]?.id || null;
    state.query = '';
    state.group = '';
    state.visibleItemLimit = itemListPageSize;
    state.draft = null;
    state.activeSectionTitle = null;
    state.dirty = false;
    $('search').value = '';
    render();
    return;
  }

  if (button.matches('.module-btn')) {
    const nextModule = button.dataset.module;
    if (!nextModule || nextModule === state.module) return;
    if (state.mustChangePassword && nextModule !== 'account') {
      notice('请先完成默认密码修改，再访问其他模块');
      return;
    }
    if (!(await confirmDiscard())) return;
    state.module = nextModule;
    if (nextModule === 'exploits') state.expSection = 'items';
    state.selectedId = singletonModules.has(nextModule) ? null : activeItems()[0]?.id || null;
    state.query = '';
    state.group = '';
    state.visibleItemLimit = itemListPageSize;
    state.draft = null;
    state.activeSectionTitle = null;
    state.logoUploadMeta = null;
    state.dirty = false;
    state.mobileView = defaultMobileView(state.module);
    $('search').value = '';
    render();
    if (state.module === 'clientBuilds') {
      loadClientBuildStatus({ quiet: true }).catch(error => notice(error.message || '刷新客户端生成状态失败'));
    }
    if (state.module === 'updates') {
      loadVersionStatus({ quiet: true }).catch(error => notice(error.message || '读取版本状态失败'));
    }
    return;
  }

  if (button.matches('.view-btn')) {
    setMobileView(button.dataset.view);
    return;
  }

  if (button.matches('.section-tab')) {
    focusSection(Number(button.dataset.sectionIndex));
    return;
  }

  if (button.matches('.section-head')) {
    const sectionNode = button.closest('.form-section');
    if (!sectionNode) return;
    if (state.module !== 'settings') {
      openSection(sectionNode);
      return;
    }
    const nextOpen = !sectionNode.classList.contains('open');
    sectionNode.classList.toggle('open', nextOpen);
    button.setAttribute('aria-expanded', nextOpen ? 'true' : 'false');
    state.sectionState[sectionKey(sectionNode.dataset.sectionTitle || '')] = nextOpen;
    renderSectionTabs();
    return;
  }

  if (button.id === 'mobile-back-list') {
    setMobileView('list');
    return;
  }

  if (button.matches('.group-btn')) {
    state.group = button.dataset.group || '';
    state.visibleItemLimit = itemListPageSize;
    render();
    return;
  }

  if (button.matches('.item-row')) {
    if (button.dataset.id === state.selectedId && !state.draft) {
      setMobileView('editor');
      return;
    }
    if (!(await confirmDiscard())) return;
    state.selectedId = button.dataset.id;
    state.draft = null;
    state.activeSectionTitle = null;
    state.logoUploadMeta = null;
    state.dirty = false;
    state.mobileView = 'editor';
    render();
    return;
  }

  const action = button.dataset.action;
  if (!action) return;

  if (action === 'load-more-items') {
    state.visibleItemLimit += itemListPageSize;
    renderList();
    return;
  }

  if (action === 'close-section') {
    closeActiveSection();
    return;
  }

  if (action === 'save-section') {
    closeActiveSection();
    saveCurrent().catch(error => notice(error.message || '保存失败'));
    return;
  }

  if (action === 'generate-client-build') {
    generateClientBuild().catch(error => notice(error.message || '生成客户端失败'));
    return;
  }

  if (action === 'refresh-client-build') {
    loadClientBuildStatus().catch(error => notice(error.message || '刷新客户端生成状态失败'));
    return;
  }

  if (action === 'remove-logo') {
    updateLogoUrl('', null);
    notice('Logo 图片已移除，请保存站点设置');
    return;
  }

  if (action === 'add-command') {
    mutateDraft(draft => {
      const sectionName = button.dataset.section;
      draft[sectionName] = Array.isArray(draft[sectionName]) ? draft[sectionName] : [];
      draft[sectionName].push(defaultCommand(commandTarget(sectionName)));
    });
  }

  if (action === 'remove-command') {
    mutateDraft(draft => {
      const sectionName = button.dataset.section;
      draft[sectionName].splice(Number(button.dataset.index), 1);
    });
  }

  if (action === 'move-command') {
    mutateDraft(draft => {
      const sectionName = button.dataset.section;
      swapArrayItem(draft[sectionName], Number(button.dataset.index), button.dataset.direction);
    });
  }

  if (action === 'add-syntax') {
    mutateDraft(draft => {
      const command = commandAt(draft, button.dataset.section, button.dataset.commandIndex);
      command.syntaxBreakdown = Array.isArray(command.syntaxBreakdown) ? command.syntaxBreakdown : [];
      command.syntaxBreakdown.push({
        part: '',
        type: 'parameter',
        explanation: { zh: '', en: '' },
      });
    });
  }

  if (action === 'remove-syntax') {
    mutateDraft(draft => {
      const command = commandAt(draft, button.dataset.section, button.dataset.commandIndex);
      command.syntaxBreakdown = Array.isArray(command.syntaxBreakdown) ? command.syntaxBreakdown : [];
      command.syntaxBreakdown.splice(Number(button.dataset.index), 1);
    });
  }

  if (action === 'move-syntax') {
    mutateDraft(draft => {
      const command = commandAt(draft, button.dataset.section, button.dataset.commandIndex);
      command.syntaxBreakdown = Array.isArray(command.syntaxBreakdown) ? command.syntaxBreakdown : [];
      swapArrayItem(command.syntaxBreakdown, Number(button.dataset.index), button.dataset.direction);
    });
  }

  if (action === 'add-example') {
    mutateDraft(draft => {
      const command = commandAt(draft, button.dataset.section, button.dataset.commandIndex);
      command.examples = Array.isArray(command.examples) ? command.examples : [];
      command.examples.push({ zh: '', en: '' });
    });
  }

  if (action === 'remove-example') {
    mutateDraft(draft => {
      const command = commandAt(draft, button.dataset.section, button.dataset.commandIndex);
      command.examples = Array.isArray(command.examples) ? command.examples : [];
      command.examples.splice(Number(button.dataset.index), 1);
    });
  }

  if (action === 'move-example') {
    mutateDraft(draft => {
      const command = commandAt(draft, button.dataset.section, button.dataset.commandIndex);
      command.examples = Array.isArray(command.examples) ? command.examples : [];
      swapArrayItem(command.examples, Number(button.dataset.index), button.dataset.direction);
    });
  }

  if (action === 'add-chain-step') {
    mutateDraft(draft => {
      draft.attackChain = Array.isArray(draft.attackChain) ? draft.attackChain : [];
      draft.attackChain.push(defaultAttackChainStep());
    });
  }

  if (action === 'remove-chain-step') {
    mutateDraft(draft => {
      draft.attackChain = Array.isArray(draft.attackChain) ? draft.attackChain : [];
      draft.attackChain.splice(Number(button.dataset.index), 1);
    });
  }

  if (action === 'move-chain-step') {
    mutateDraft(draft => {
      draft.attackChain = Array.isArray(draft.attackChain) ? draft.attackChain : [];
      swapArrayItem(draft.attackChain, Number(button.dataset.index), button.dataset.direction);
    });
  }

  if (action === 'add-nav-root-child') {
    mutateDraft(draft => {
      draft.children = Array.isArray(draft.children) ? draft.children : [];
      draft.children.push(defaultNav());
    });
  }

  if (action === 'add-nav-child') {
    mutateDraft(draft => {
      const list = getNavListAtPath(draft, button.dataset.path);
      list.push(defaultNav());
    });
  }

  if (action === 'remove-nav-node') {
    mutateDraft(draft => {
      const list = getNavListAtPath(draft, button.dataset.path, true);
      list.splice(navPathParts(button.dataset.path).at(-1), 1);
    });
  }

  if (action === 'move-nav-node') {
    mutateDraft(draft => {
      const list = getNavListAtPath(draft, button.dataset.path, true);
      swapArrayItem(list, navPathParts(button.dataset.path).at(-1), button.dataset.direction);
    });
  }

  // ---- EXP 表单：行增删直接操作 DOM（DOM 即编辑态，保存时全量收集）----
  if (action === 'add-exp-vuln') {
    const collection = $('editor-form')?.querySelector('.exp-row-card[data-section="vulnerabilityIds"]')?.parentElement;
    if (!collection) return;
    const nextIndex = Math.max(-1, [...collection.querySelectorAll('.exp-row-card[data-section="vulnerabilityIds"]')]
      .map(row => Number(row.dataset.index)).reduce((a, b) => Math.max(a, b), -1)) + 1;
    collection.insertAdjacentHTML('beforeend', exploitVulnIdRow({}, nextIndex));
    setDirty(true);
    return;
  }

  if (action === 'remove-exp-vuln') {
    button.closest('.exp-row-card[data-section="vulnerabilityIds"]')?.remove();
    setDirty(true);
    return;
  }

  if (action === 'add-exp-code') {
    const collection = $('editor-form')?.querySelector('.exp-row-card[data-section="exploitCode"]')?.parentElement;
    if (!collection) return;
    const nextIndex = [...collection.querySelectorAll('.exp-row-card[data-section="exploitCode"]')]
      .map(row => Number(row.dataset.index)).reduce((a, b) => Math.max(a, b), -1) + 1;
    collection.insertAdjacentHTML('beforeend', exploitCodeRow({}, nextIndex));
    setDirty(true);
    return;
  }

  if (action === 'remove-exp-code') {
    button.closest('.exp-row-card[data-section="exploitCode"]')?.remove();
    setDirty(true);
    return;
  }

  if (action === 'restore-exploit') {
    const id = $('exploit-id')?.value.trim();
    if (!id) return;
    api(`/api/admin/exploits/${encodeURIComponent(id)}/restore`, { method: 'POST' })
      .then(() => loadAll())
      .then(() => notice('已恢复显示'))
      .catch(error => notice(error.message || '恢复失败'));
    return;
  }

  if (action === 'add-expnode-root-child') {
    mutateDraft(draft => {
      draft.children = Array.isArray(draft.children) ? draft.children : [];
      draft.children.push(defaultExpNode());
    });
  }

  if (action === 'add-expnode-child') {
    mutateDraft(draft => {
      const list = getNavListAtPath(draft, button.dataset.path);
      list.push(defaultExpNode());
    });
  }

  if (action === 'remove-expnode-node') {
    mutateDraft(draft => {
      const list = getNavListAtPath(draft, button.dataset.path, true);
      list.splice(navPathParts(button.dataset.path).at(-1), 1);
    });
  }

  if (action === 'move-expnode-node') {
    mutateDraft(draft => {
      const list = getNavListAtPath(draft, button.dataset.path, true);
      swapArrayItem(list, navPathParts(button.dataset.path).at(-1), button.dataset.direction);
    });
  }
});

$('editor-form').addEventListener('submit', event => {
  event.preventDefault();
  if (state.module === 'clientBuilds' || state.module === 'updates') return;
  saveCurrent().catch(error => notice(error.message || '保存失败'));
});

$('editor-form').addEventListener('input', () => {
  if (state.module === 'clientBuilds' || state.module === 'updates') return;
  if (state.rendering || state.loading || state.saving) return;
  if (state.module === 'account') {
    syncPasswordMatchHint();
    setDirty(true);
    return;
  }
  try {
    state.draft = collectCurrentForm();
    setDirty(true);
  } catch {
    setDirty(true);
  }
});

$('editor-form').addEventListener('change', event => {
  if (state.module === 'clientBuilds') {
    const input = event.target?.closest?.('input[data-client-target]');
    if (!input) return;
    const selected = ensureClientBuildSelectedTargets();
    if (input.checked) selected.add(input.dataset.clientTarget);
    else selected.delete(input.dataset.clientTarget);
    renderClientBuildFormV2();
    return;
  }
  if (state.module === 'updates') return;
  if (state.rendering || state.loading || state.saving) return;
  if (state.module === 'account') {
    setDirty(true);
    return;
  }
  if (event.target?.id === 'logo-upload') {
    const file = event.target.files?.[0];
    event.target.value = '';
    uploadLogoFile(file).catch(error => notice(error.message || 'Logo 上传失败'));
    return;
  }
  try {
    state.draft = collectCurrentForm();
  } catch {
    state.draft = state.draft || clone(selectedItem());
  }
  setDirty(true);
});

$('new-item').onclick = newItem;
$('save-current').onclick = () => saveCurrent().catch(error => notice(error.message || '保存失败'));
$('cancel-current').onclick = cancelCurrentEdit;
$('move-up').onclick = () => moveSelected('up').catch(error => notice(error.message || '移动失败'));
$('move-down').onclick = () => moveSelected('down').catch(error => notice(error.message || '移动失败'));
$('delete-item').onclick = () => deleteSelected().catch(error => notice(error.message || '删除失败'));
$('mobile-move-up').onclick = () => moveSelected('up').catch(error => notice(error.message || '移动失败'));
$('mobile-move-down').onclick = () => moveSelected('down').catch(error => notice(error.message || '移动失败'));
$('mobile-delete-item').onclick = () => deleteSelected().catch(error => notice(error.message || '删除失败'));
$('open-import').onclick = openImportModal;
$('logout-admin').onclick = () => logoutAdmin();
$('reset-module').onclick = () => resetCurrent(moduleConfig().reset).catch(error => notice(error.message || '重置默认数据失败'));
$('reset-all').onclick = () => resetCurrent('all').catch(error => notice(error.message || '重置默认数据失败'));
$('close-import').onclick = closeImportModal;
$('confirm-modal-cancel').onclick = () => closeConfirmModal(false);
$('confirm-modal-confirm').onclick = () => closeConfirmModal(true);
$('confirm-modal-gate-input').oninput = event => {
  const confirmButton = $('confirm-modal-confirm');
  if (confirmButton) confirmButton.disabled = String(event.target.value || '') !== confirmModal.requireText;
};
$('confirm-modal-gate-input').onkeydown = event => {
  if (event.key !== 'Enter') return;
  event.preventDefault();
  const confirmButton = $('confirm-modal-confirm');
  if (confirmButton && !confirmButton.disabled) closeConfirmModal(true);
};
$('download-template').onclick = () => downloadImportTemplate().catch(error => notice(error.message || '下载导入模板失败'));
$('preview-import').onclick = () => previewImportData().catch(error => notice(error.message || '导入预览失败'));
$('run-import').onclick = () => runImportData().catch(error => notice(error.message || '数据导入失败'));
$('import-file').onchange = event => {
  const file = event.target.files?.[0] || null;
  event.target.value = '';
  selectImportFile(file).catch(error => notice(error.message || '读取导入文件失败'));
};
for (const input of document.querySelectorAll('input[name="import-mode"]')) {
  input.onchange = event => {
    state.importMode = event.target.value === 'replace' ? 'replace' : 'merge';
    state.importPreview = null;
    state.importResult = null;
    state.importError = '';
    renderImportModal();
  };
}
$('clear-filter').onclick = () => {
  state.query = '';
  state.group = '';
  state.visibleItemLimit = itemListPageSize;
  $('search').value = '';
  const groupSelect = $('group-select');
  if (groupSelect) groupSelect.value = '';
  render();
};
$('search').oninput = event => {
  state.query = event.target.value;
  state.visibleItemLimit = itemListPageSize;
  renderList();
};
$('group-select').onchange = event => {
  state.group = event.target.value;
  state.visibleItemLimit = itemListPageSize;
  render();
};

const setMoreActionsOpen = open => {
  const trigger = $('more-actions');
  const menu = $('more-actions-menu');
  if (!trigger || !menu) return;
  trigger.setAttribute('aria-expanded', String(open));
  menu.classList.toggle('hidden', !open);
};

$('more-actions').onclick = () => {
  setMoreActionsOpen($('more-actions').getAttribute('aria-expanded') !== 'true');
};

$('admin-module-select').onchange = event => {
  document.querySelector(`.module-btn[data-module="${event.target.value}"]`)?.click();
};

document.addEventListener('click', event => {
  if (event.target?.id === 'cancel-item') {
    cancelCurrentEdit();
  }
  if (event.target?.id === 'import-modal') {
    closeImportModal();
  }
  if (event.target?.id === 'confirm-modal') {
    closeConfirmModal(false);
  }
  if (!event.target.closest('.more-actions') || event.target.closest('.action-menu-item')) {
    setMoreActionsOpen(false);
  }
});

document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && confirmModal.open) {
    closeConfirmModal(false);
    return;
  }
  if (event.key === 'Escape' && $('more-actions').getAttribute('aria-expanded') === 'true') {
    setMoreActionsOpen(false);
    $('more-actions').focus();
    return;
  }
  if (event.key === 'Escape' && state.importOpen) {
    closeImportModal();
    return;
  }
  if (event.key === 'Escape' && state.activeSectionTitle) {
    closeActiveSection();
    return;
  }
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
    if (state.module === 'clientBuilds' || state.module === 'updates' || state.saving || state.loading) return;
    if (!state.dirty && !state.draft) return;
    event.preventDefault();
    saveCurrent().catch(error => notice(error.message || '保存失败'));
  }
});

ensureNavCollapseButton();

window.addEventListener('beforeunload', event => {
  if (!state.dirty) return;
  event.preventDefault();
  event.returnValue = '';
});

loadAll()
  .then(() => {
    const initialModule = sessionStorage.getItem('payloader-admin-initial-module');
    sessionStorage.removeItem('payloader-admin-initial-module');
    if (initialModule === 'custom') document.querySelector('.module-btn[data-module="custom"]')?.click();
  })
  .catch(error => notice(error.message || '加载失败'));
