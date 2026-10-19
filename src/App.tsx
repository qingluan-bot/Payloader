import { lazy, Suspense, useState, useEffect, useMemo, useCallback, useDeferredValue, useRef } from 'react';
import { useMantineColorScheme } from '@mantine/core';
// 全局样式必须在组件 import 之前，保证 bundle 中先于组件 CSS（组件 <style> 迁出后级联改由 import 顺序决定）
import './styles/global.css';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import MainContent from './components/MainContent';
import MobileNav from './components/MobileNav';
import CopyToast from './components/CopyToast';
import { MOBILE_BREAKPOINT, useMediaQuery } from './components/useMediaQuery';
import {
  LanguageContext,
  NavContext,
  SearchContext,
  SessionContext,
  StaticDataContext,
} from './appContext';
import type { ActiveTab, ActiveView, PayloadMode, ThemeMode } from './appContext';
import { emptyPublicData, parsePublicData } from './data/publicData';
import { ensurePayloadSearchCorpus, payloadCorpusIsReady } from './data/payloadSearchCorpus';
import type { PayloadSearchCorpus } from './data/payloadSearchCorpus';
import type { GlobalVariable, PublicClientBuildInfo, PublicData } from './types';
import type { Language } from './i18n';
import { getText } from './i18n';
import { buildSearchIndex, matchSearchIndex } from './searchIndex';
import { applyPageSeo, installDeepLinking, pushHashForState, readRouteFromHash, syncHashForState } from './utils/seo';
import type { RouteState } from './utils/seo';
// 移动端样式必须位于全部组件 import 之后：bundle 内级联压过存量断点规则（见 c699589 同理）
import './styles/mobile.css';

const LazyEncodingTools = lazy(() => import('./components/EncodingTools'));

// 全局变量（硬编码治理批）：默认值随 /api/public-data 的 DB 权威下发；用户编辑过的存档
// 优先（localStorage），离线/无存档时空起步——前端不再打包 212 行硬编码默认值。
const VARIABLES_STORAGE_KEY = 'cyber-arsenal-variables';

function App() {
  const [globalVariables, setGlobalVariables] = useState<GlobalVariable[]>(() => {
    try {
      const saved = localStorage.getItem(VARIABLES_STORAGE_KEY);
      if (saved) {
        const parsed: unknown = JSON.parse(saved);
        if (Array.isArray(parsed)) return parsed.filter((item): item is GlobalVariable =>
          Boolean(item && typeof item === 'object' && typeof item.key === 'string' && typeof item.value === 'string'));
      }
    } catch { /* ignore */ }
    return [];
  });
  const [publicData, setPublicData] = useState<PublicData>(() => emptyPublicData());
  const [clientBuildInfo, setClientBuildInfo] = useState<PublicClientBuildInfo | null>(null);
  const [dataLoading, setDataLoading] = useState(true);
  const [dataError, setDataError] = useState<string | null>(null);
  const isPackagedOfflineClient = window.location.protocol === 'payloader:';
  const allPayloads = useMemo(() => publicData.payloads, [publicData.payloads]);
  const allToolCommands = useMemo(() => publicData.tools, [publicData.tools]);
  const allPayloadNavigation = useMemo(() => publicData.navigation, [publicData.navigation]);
  const allToolNavigation = useMemo(() => publicData.toolNavigation, [publicData.toolNavigation]);
  const allExploits = useMemo(() => publicData.exploits ?? [], [publicData.exploits]);
  const allExploitNavigation = useMemo(() => publicData.exploitNavigation ?? [], [publicData.exploitNavigation]);
  const settings = useMemo(() => publicData.settings, [publicData.settings]);
  const ctfCheatsheets = useMemo(() => publicData.ctfCheatsheets ?? {}, [publicData.ctfCheatsheets]);

  // 深链初始态：初始 state 直接从 hash 恢复——若等 installDeepLinking 的 effect 恢复，
  // 先声明的 syncHashForState effect 会用初始值覆写 hash，深链在解析前就被清洗掉
  const initialRoute = readRouteFromHash();
  const [selectedPayloadId, setSelectedPayloadId] = useState<string | null>(initialRoute?.payloadId ?? null);
  const [selectedToolId, setSelectedToolId] = useState<string | null>(initialRoute?.toolId ?? null);
  const [selectedExploitId, setSelectedExploitId] = useState<string | null>(initialRoute?.exploitId ?? null);
  const [selectedExploitTypeId, setSelectedExploitTypeId] = useState<string | null>(initialRoute?.exploitTypeId ?? null);
  // 移动端 payload/工具 分类浏览态（不进 hash，刷新回全部分类）
  const [mobileCategoryId, setMobileCategoryId] = useState<string | null>(null);
  const [bypassMode, setBypassMode] = useState<PayloadMode>(initialRoute?.waf ? 'waf' : 'normal');
  const [activeTab, setActiveTab] = useState<ActiveTab>((initialRoute?.tab as ActiveTab) || 'payloads');
  // B-6：#/downloads 深链直达下载客户端视图（初始态同 hash 恢复，刷新可用）
  const [activeView, setActiveView] = useState<ActiveView>(initialRoute?.downloads ? 'clientDownloads' : 'workspace');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => window.matchMedia('(max-width: 900px)').matches);
  const [searchQuery, setSearchQuery] = useState('');
  // CTF 工作台全局密钥（批次 M）：跨工作台实例共享（智能识别 hero ↔ 密码工作台 ↔ 渗透编解码），
  // Vigenère → AES 等多步连用时密钥只填一次；会话级状态，不落盘。
  const [globalSecret, setGlobalSecret] = useState('');
  // The public language switch stays disabled until English content passes coverage checks.
  const [language, setLanguage] = useState<Language>('zh');
  const [settledSearchQuery, setSettledSearchQuery] = useState('');
  const deferredSearchQuery = useDeferredValue(settledSearchQuery);
  // P1-2 搜索语料：命令文本延迟拉取（空闲预取 + 搜索触发重试），并入 payload 搜索索引
  const [payloadCommandCorpus, setPayloadCommandCorpus] = useState<PayloadSearchCorpus>(() => new Map());
  const searchIndex = useMemo(
    () => buildSearchIndex(allPayloads, allToolCommands, allExploits, language, payloadCommandCorpus),
    [allPayloads, allToolCommands, allExploits, language, payloadCommandCorpus],
  );
  const searchMatches = useMemo(
    () => matchSearchIndex(searchIndex, deferredSearchQuery),
    [deferredSearchQuery, searchIndex],
  );
  const closeSidebar = useCallback(() => setSidebarCollapsed(true), []);
  // 移动模式（≤768px）：底部导航接管主导航、侧栏不挂载、Header 桌面控件隐藏（mobile.css）。
  const isMobile = useMediaQuery(MOBILE_BREAKPOINT);

  useEffect(() => {
    const timer = window.setTimeout(
      () => setSettledSearchQuery(searchQuery),
      searchQuery ? 80 : 0,
    );
    return () => window.clearTimeout(timer);
  }, [searchQuery]);

  // 搜索语料空闲预取：首屏关键路径不受影响；用户直接搜索时由下方 effect 兜底触发
  useEffect(() => {
    let isCurrent = true;
    const apply = (map: PayloadSearchCorpus) => {
      if (isCurrent && map.size) setPayloadCommandCorpus(map);
    };
    if (typeof window.requestIdleCallback === 'function') {
      const idleId = window.requestIdleCallback(() => {
        void ensurePayloadSearchCorpus().then(apply);
      }, { timeout: 4000 });
      return () => {
        isCurrent = false;
        window.cancelIdleCallback(idleId);
      };
    }
    const timer = window.setTimeout(() => {
      void ensurePayloadSearchCorpus().then(apply);
    }, 2500);
    return () => {
      isCurrent = false;
      window.clearTimeout(timer);
    };
  }, []);

  // 搜索触发兜底：用户键入时语料仍未就绪（预取失败/未跑）则再拉一次（模块内去重+退避）
  useEffect(() => {
    if (!deferredSearchQuery.trim() || payloadCorpusIsReady()) return;
    void ensurePayloadSearchCorpus().then(map => {
      if (map.size) setPayloadCommandCorpus(map);
    });
  }, [deferredSearchQuery]);

  // Theme with localStorage persistence
  const [theme, setTheme] = useState<ThemeMode>(() => {
    try {
      const saved = localStorage.getItem('cyber-arsenal-theme');
      return (saved === 'light' || saved === 'dark') ? saved : 'dark';
    } catch {
      return 'dark';
    }
  });
  const { setColorScheme } = useMantineColorScheme();

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    setColorScheme(theme);
    try {
      localStorage.setItem('cyber-arsenal-theme', theme);
    } catch { /* ignore */ }
  }, [theme, setColorScheme]);

  // 变量编辑持久化：一旦用户动过变量，全量落 localStorage；刷新后存档优先于 DB 默认（现场不丢）。
  const variablesTouchedRef = useRef(false);
  useEffect(() => {
    if (!variablesTouchedRef.current) return;
    try {
      localStorage.setItem(VARIABLES_STORAGE_KEY, JSON.stringify(globalVariables));
    } catch { /* ignore */ }
  }, [globalVariables]);
  const updateGlobalVariables = useCallback((next: GlobalVariable[]) => {
    variablesTouchedRef.current = true;
    setGlobalVariables(next);
  }, []);

  // SEO：title/description/OG 跟随当前选中内容页（payload/工具），无选中回落站点默认
  const seoSubject = useMemo(() => {
    if (selectedPayloadId) {
      const p = allPayloads.find(item => item.id === selectedPayloadId);
      return p ? { title: getText(p.name, language), description: getText(p.description, language) } : null;
    }
    if (selectedToolId) {
      const t = allToolCommands.find(item => item.id === selectedToolId);
      return t ? { title: getText(t.name, language), description: getText(t.description, language) } : null;
    }
    if (selectedExploitId) {
      const e = allExploits.find(item => item.id === selectedExploitId);
      return e ? { title: e.name, description: e.description } : null;
    }
    return null;
  }, [selectedPayloadId, selectedToolId, selectedExploitId, allPayloads, allToolCommands, allExploits, language]);

  const fallbackBrowserTitle = getText(settings.browserTitle, language) || 'Payloader';
  const fallbackDescription = language === 'zh'
    ? '面向授权安全测试与研究的本地知识工作台，提供可检索的载荷与工具命令、变量替换、内容管理、离线客户端和编解码工具。'
    : 'A local security knowledge workbench with searchable payloads, tool commands, variable replacement, content management, offline clients, and codec utilities.';

  useEffect(() => {
    applyPageSeo(seoSubject, fallbackBrowserTitle, fallbackDescription);
  }, [seoSubject, fallbackBrowserTitle, fallbackDescription]);

  useEffect(() => {
    document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en';
  }, [language]);

  // 深链路由：选中状态 → hash URL（可分享/可收藏）；挂载与后退时从 URL 恢复
  // B-6：进入下载页用 push 留历史条目（浏览器后退回到原视图），其余选中切换维持 replace
  const prevViewRef = useRef<ActiveView>(initialRoute?.downloads ? 'clientDownloads' : 'workspace');
  useEffect(() => {
    const routeState: RouteState = { tab: activeTab, payloadId: selectedPayloadId, toolId: selectedToolId, exploitId: selectedExploitId, exploitTypeId: selectedExploitTypeId, waf: bypassMode === 'waf', downloads: activeView === 'clientDownloads' };
    const enteringDownloads = activeView === 'clientDownloads' && prevViewRef.current !== 'clientDownloads';
    prevViewRef.current = activeView;
    if (enteringDownloads) pushHashForState(routeState);
    else syncHashForState(routeState);
  }, [activeTab, activeView, selectedPayloadId, selectedToolId, selectedExploitId, selectedExploitTypeId, bypassMode]);

  useEffect(() => installDeepLinking(route => {
    if (!route) return;
    // B-6：#/downloads ↔ 工作台视图（后退/前进恢复原视图）；downloads 路由不动 tab
    if (route.downloads && activeView !== 'clientDownloads') setActiveView('clientDownloads');
    if (!route.downloads && activeView === 'clientDownloads') setActiveView('workspace');
    if (route.tab && !route.downloads && route.tab !== activeTab) {
      setActiveTab(route.tab as ActiveTab);
      // hash 切 tab 不走 switchTab，移动分类浏览态一并清掉
      setMobileCategoryId(null);
    }
    if (route.waf !== (bypassMode === 'waf')) setBypassMode(route.waf ? 'waf' : 'normal');
    if (route.payloadId !== selectedPayloadId) setSelectedPayloadId(route.payloadId);
    if (route.toolId !== selectedToolId) setSelectedToolId(route.toolId);
    if (route.exploitId !== selectedExploitId) setSelectedExploitId(route.exploitId);
    if (route.exploitTypeId !== selectedExploitTypeId) setSelectedExploitTypeId(route.exploitTypeId);
  }), [activeTab, activeView, bypassMode, selectedPayloadId, selectedToolId, selectedExploitId, selectedExploitTypeId]);

  useEffect(() => {
    const media = window.matchMedia('(max-width: 900px)');
    const apply = () => setSidebarCollapsed(media.matches);
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, []);

  useEffect(() => {
    let isCurrent = true;

    fetch('/api/public-data')
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (isCurrent) {
          const parsed = parsePublicData(data);
          setPublicData(parsed);
          // 无用户存档时以 DB 默认变量起步（不触发编辑持久化标记）。
          if (parsed.globalVariables?.length && !localStorage.getItem(VARIABLES_STORAGE_KEY)) {
            setGlobalVariables(parsed.globalVariables);
          }
          setDataError(null);
        }
      })
      .catch(error => {
        if (isCurrent) {
          setPublicData(emptyPublicData());
          setDataError(error instanceof Error ? error.message : 'Failed to load data');
        }
      })
      .finally(() => {
        if (isCurrent) {
          setDataLoading(false);
        }
      });

    return () => {
      isCurrent = false;
    };
  }, []);

  const refreshClientBuildInfo = useCallback(async (signal?: AbortSignal) => {
    if (isPackagedOfflineClient) {
      setClientBuildInfo(null);
      return;
    }
    try {
      const response = await fetch('/api/client-build', {
        method: 'GET',
        signal,
        cache: 'no-store',
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      if (data?.offlineClient) {
        setClientBuildInfo(null);
        return;
      }
      setClientBuildInfo(data);
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        return;
      }
      setClientBuildInfo(null);
    }
  }, [isPackagedOfflineClient]);

  useEffect(() => {
    if (isPackagedOfflineClient) return;
    const controller = new AbortController();
    const initialTimer = window.setTimeout(() => {
      void refreshClientBuildInfo(controller.signal);
    }, 0);

    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        void refreshClientBuildInfo();
      }
    }, 15000);

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        void refreshClientBuildInfo();
      }
    };

    window.addEventListener('focus', handleVisibilityChange);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      controller.abort();
      window.clearTimeout(initialTimer);
      window.clearInterval(timer);
      window.removeEventListener('focus', handleVisibilityChange);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [refreshClientBuildInfo, isPackagedOfflineClient]);

  // 5 个 context value 按域 useMemo：域内字段不变时保持引用稳定，消费组件据此跳过重渲染。
  const staticDataValue = useMemo(
    () => ({
      allPayloads,
      allToolCommands,
      allPayloadNavigation,
      allToolNavigation,
      allExploits,
      allExploitNavigation,
      settings,
      ctfCheatsheets,
      dataLoading,
      dataError,
    }),
    [allPayloads, allToolCommands, allPayloadNavigation, allToolNavigation, allExploits, allExploitNavigation, settings, ctfCheatsheets, dataLoading, dataError],
  );
  const languageValue = useMemo(() => ({ language, setLanguage }), [language]);
  const navValue = useMemo(
    () => ({
      activeTab,
      setActiveTab,
      activeView,
      setActiveView,
      selectedPayloadId,
      setSelectedPayloadId,
      selectedToolId,
      setSelectedToolId,
      selectedExploitId,
      setSelectedExploitId,
      selectedExploitTypeId,
      setSelectedExploitTypeId,
      mobileCategoryId,
      setMobileCategoryId,
      bypassMode,
      setBypassMode,
    }),
    [activeTab, activeView, selectedPayloadId, selectedToolId, selectedExploitId, selectedExploitTypeId, mobileCategoryId, bypassMode],
  );
  const searchValue = useMemo(
    () => ({ searchQuery, setSearchQuery, deferredSearchQuery, searchMatches, payloadCommandCorpus }),
    [searchQuery, deferredSearchQuery, searchMatches, payloadCommandCorpus],
  );
  const sessionValue = useMemo(
    () => ({ globalVariables, setGlobalVariables: updateGlobalVariables, theme, setTheme, globalSecret, setGlobalSecret }),
    [globalVariables, updateGlobalVariables, theme, globalSecret],
  );
  // 编解码工具 slot：桌面头部弹层与移动端「更多」页共用同一份 lazy 内容。
  const encodingToolsSlot = useMemo(() => (
    <Suspense fallback={<div className="lazy-loading" role="status" aria-live="polite">正在加载编解码工具...</div>}>
      <LazyEncodingTools />
    </Suspense>
  ), []);
  // 引用稳定回调：内联箭头会在 App 每次渲染（含搜索键入）时换引用，击穿下游 memo。
  const openClientDownloads = useCallback(() => {
    setActiveView('clientDownloads');
    setSelectedPayloadId(null);
    setSelectedToolId(null);
    setSelectedExploitId(null);
    setSearchQuery('');
  }, [setActiveView, setSelectedPayloadId, setSelectedToolId, setSelectedExploitId, setSearchQuery]);
  const handleSidebarNavigate = useCallback(() => {
    setActiveView('workspace');
    if (window.matchMedia('(max-width: 900px)').matches) {
      setSidebarCollapsed(true);
    }
  }, [setActiveView]);

  return (
    <StaticDataContext.Provider value={staticDataValue}>
      <LanguageContext.Provider value={languageValue}>
        <NavContext.Provider value={navValue}>
          <SearchContext.Provider value={searchValue}>
            <SessionContext.Provider value={sessionValue}>
              <div className="app-container">
                <a className="skip-link" href="#main-content">跳到主要内容</a>
                <Header
                  sidebarCollapsed={sidebarCollapsed}
                  setSidebarCollapsed={setSidebarCollapsed}
                  clientBuildInfo={clientBuildInfo}
                  showClientDownloads={!isPackagedOfflineClient}
                  encodingTools={encodingToolsSlot}
                  onOpenClientDownloads={openClientDownloads}
                />
                <div className="main-layout">
                  {!isMobile && activeTab !== 'ctf' && (
                    <>
                      <Sidebar
                        collapsed={sidebarCollapsed}
                        onClose={closeSidebar}
                        onNavigate={handleSidebarNavigate}
                      />
                      {!sidebarCollapsed && (
                        <button
                          className="sidebar-backdrop"
                          onClick={closeSidebar}
                          aria-label="关闭导航"
                        />
                      )}
                    </>
                  )}
                  <MainContent
                    clientBuildInfo={clientBuildInfo}
                    encodingTools={encodingToolsSlot}
                    onOpenClientDownloads={openClientDownloads}
                    showClientDownloads={!isPackagedOfflineClient}
                  />
                </div>
                {isMobile && <MobileNav />}
                {isMobile && <CopyToast />}
              </div>
            </SessionContext.Provider>
          </SearchContext.Provider>
        </NavContext.Provider>
      </LanguageContext.Provider>
    </StaticDataContext.Provider>
  );
}

export default App;
