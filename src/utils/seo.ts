// SPA 深链路由与动态 SEO：状态 ↔ hash URL 双向同步 + 每内容页独立 title/description/OG。
// 纯客户端路由（hash 形态）保证本地/离线/公网三种部署一致可用，sitemap 由服务端从 DB 生成。

export type RouteState = {
  tab: string;
  payloadId: string | null;
  toolId: string | null;
  exploitId: string | null;
  exploitTypeId: string | null;
  waf: boolean;
  /** B-6：下载客户端视图独立 hash（#/downloads），刷新/后退可用 */
  downloads?: boolean;
};

const parseHash = (hash: string): RouteState | null => {
  const m = hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  if (!m.length) return null;
  const [kind, id, mode] = m;
  if (kind === 'payload' && id) return { tab: 'payloads', payloadId: id, toolId: null, exploitId: null, exploitTypeId: null, waf: mode === 'waf' };
  if (kind === 'tool' && id) return { tab: 'tools', payloadId: null, toolId: id, exploitId: null, exploitTypeId: null, waf: false };
  if (kind === 'exploit' && id) return { tab: 'exploits', payloadId: null, toolId: null, exploitId: id, exploitTypeId: null, waf: false };
  if (kind === 'exploit-type' && id) return { tab: 'exploits', payloadId: null, toolId: null, exploitId: null, exploitTypeId: id, waf: false };
  if (kind === 'downloads') return { tab: 'payloads', payloadId: null, toolId: null, exploitId: null, exploitTypeId: null, waf: false, downloads: true };
  if (kind === 'tab' && id) return { tab: id, payloadId: null, toolId: null, exploitId: null, exploitTypeId: null, waf: false };
  return null;
};

export const buildHash = (state: RouteState): string => {
  if (state.downloads) return '#/downloads';
  if (state.payloadId) return `#/payload/${state.payloadId}${state.waf ? '/waf' : ''}`;
  if (state.toolId) return `#/tool/${state.toolId}`;
  if (state.exploitId) return `#/exploit/${state.exploitId}`;
  if (state.exploitTypeId) return `#/exploit-type/${state.exploitTypeId}`;
  if (state.tab && state.tab !== 'workspace') return `#/tab/${state.tab}`;
  return '#/';
};

export const readRouteFromHash = (): RouteState | null => parseHash(window.location.hash);

const applyRoute = (route: RouteState | null, apply: (r: RouteState) => void) => {
  if (route) apply(route);
};

// 最近一次由状态同步写入的 hash。BottomSheet 等占位 push/back 会让浏览器对「同 hash」
// 的历史条目导航也触发 hashchange；hash 未变化时不重放路由，避免用户刚做的选中被旧 hash 状态清掉。
let lastSyncedHash: string | null = null;

// 挂载/后退恢复 + 状态变化写 URL。onRoute 由 App 提供：把路由态落到 React state。
export const installDeepLinking = (onRoute: (route: RouteState | null) => void): (() => void) => {
  const handler = () => {
    if (window.location.hash === lastSyncedHash) return;
    onRoute(parseHash(window.location.hash));
  };
  window.addEventListener('hashchange', handler);
  applyRoute(parseHash(window.location.hash), onRoute);
  return () => window.removeEventListener('hashchange', handler);
};

export const syncHashForState = (state: RouteState) => {
  const next = buildHash(state);
  lastSyncedHash = next;
  if (window.location.hash !== next) {
    // replaceState：选中切换不堆历史，后退始终回到上一个稳定入口
    window.history.replaceState(null, '', next);
  }
};

// B-6：视图级切换（进入下载页）用 push 留历史条目——浏览器后退可回到原视图，
// 后退触发 hashchange 时 lastSyncedHash 守卫与 syncHashForState 同一套语义。
export const pushHashForState = (state: RouteState) => {
  const next = buildHash(state);
  lastSyncedHash = next;
  if (window.location.hash !== next) {
    window.history.pushState(null, '', next);
  }
};

const setMeta = (selector: string, content: string) => {
  document.querySelector(selector)?.setAttribute('content', content);
};

export interface SeoSubject {
  title: string;
  description: string;
}

// 每内容页独立 SEO 元数据：title 跟随卡片名，description 取卡描述前 150 字，OG 与 canonical 同步。
export const applyPageSeo = (subject: SeoSubject | null, fallbackTitle: string, fallbackDescription: string) => {
  const title = subject?.title?.trim() ? `${subject.title.trim()} - Payloader` : fallbackTitle;
  const description = subject?.description?.trim() ? subject.description.trim().slice(0, 150) : fallbackDescription;
  document.title = title;
  setMeta('meta[name="description"]', description);
  setMeta('meta[property="og:title"]', title);
  setMeta('meta[property="og:description"]', description);
  setMeta('meta[name="twitter:title"]', title);
  setMeta('meta[name="twitter:description"]', description);
  // 内容页 canonical 指向自身深链（hash 路由），站点根回落 /
  let canonical = document.querySelector('link[rel="canonical"]');
  if (!canonical) {
    canonical = document.createElement('link');
    canonical.setAttribute('rel', 'canonical');
    document.head.appendChild(canonical);
  }
  const path = window.location.pathname || '/';
  canonical.setAttribute('href', subject ? `${path}${buildHashFromSubject()}` : path);
};

const buildHashFromSubject = () => window.location.hash || '#/';
