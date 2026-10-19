import { createContext, useContext, useMemo } from 'react';
import type { Language } from './i18n';
import type { CheatSheet, ExploitItem, GlobalVariable, NavItem, PayloadItem, SiteSettings, ToolCommand } from './types';
import type { SearchMatches } from './searchIndex';
import type { PayloadSearchCorpus } from './data/payloadSearchCorpus';

export type ThemeMode = 'dark' | 'light';
export type ActiveTab = 'payloads' | 'tools' | 'exploits' | 'ctf';
// 'more' 仅为移动端「更多」页（MobileNav 第四项）；桌面导航不会产生该值。
export type ActiveView = 'workspace' | 'clientDownloads' | 'more';
export type PayloadMode = 'normal' | 'waf';

// ① 静态数据：启动加载后恒定的 publicData 切片与加载状态。消费面最广、变更频率最低。
export interface StaticDataContextType {
  allPayloads: PayloadItem[];
  allToolCommands: ToolCommand[];
  allPayloadNavigation: NavItem[];
  allToolNavigation: NavItem[];
  allExploits: ExploitItem[];
  allExploitNavigation: NavItem[];
  settings: SiteSettings;
  // CTF 题型速查（硬编码治理批）：随 /api/public-data 的 DB 权威下发，前端不再打包静态种子。
  ctfCheatsheets: Record<string, CheatSheet>;
  dataLoading: boolean;
  dataError: string | null;
}

// ② 语言：消费组件只读，切换频率极低；独立成域让搜索/导航等高频更新不再波及它们。
export interface LanguageContextType {
  language: Language;
  setLanguage: React.Dispatch<React.SetStateAction<Language>>;
}

// ③ 导航：写方是四个导航入口（Header/Sidebar/MainContent/CheatsheetSection）。
export interface NavContextType {
  activeTab: ActiveTab;
  setActiveTab: React.Dispatch<React.SetStateAction<ActiveTab>>;
  activeView: ActiveView;
  setActiveView: React.Dispatch<React.SetStateAction<ActiveView>>;
  selectedPayloadId: string | null;
  setSelectedPayloadId: React.Dispatch<React.SetStateAction<string | null>>;
  selectedToolId: string | null;
  setSelectedToolId: React.Dispatch<React.SetStateAction<string | null>>;
  selectedExploitId: string | null;
  setSelectedExploitId: React.Dispatch<React.SetStateAction<string | null>>;
  /** EXP 分类树类型节点浏览态（值为节点 id，如 web-app-rce）——点左树类型节点进入该漏洞类型全量列表 */
  selectedExploitTypeId: string | null;
  setSelectedExploitTypeId: React.Dispatch<React.SetStateAction<string | null>>;
  /** 移动端 payload/工具 分类浏览态（导航树分类节点 id）：MobileCategoryBar 的 sheet 选中分类后进入该分类条目列表 */
  mobileCategoryId: string | null;
  setMobileCategoryId: React.Dispatch<React.SetStateAction<string | null>>;
  bypassMode: PayloadMode;
  setBypassMode: React.Dispatch<React.SetStateAction<PayloadMode>>;
}

// ④ 搜索：唯一高频族（每次键入 value 换引用），消费面仅 Header/MainContent/Sidebar。
export interface SearchContextType {
  searchQuery: string;
  setSearchQuery: React.Dispatch<React.SetStateAction<string>>;
  deferredSearchQuery: string;
  searchMatches: SearchMatches;
  // P1-2 搜索语料（命令文本）：App 空闲/首次搜索时延迟拉取后注入，
  // Header 下拉预览索引与整页搜索共用，保证命令内容搜索不回归
  payloadCommandCorpus: PayloadSearchCorpus;
}

// ⑤ 会话：会话内用户可变数据。
export interface SessionContextType {
  globalVariables: GlobalVariable[];
  setGlobalVariables: (next: GlobalVariable[]) => void;
  theme: ThemeMode;
  setTheme: React.Dispatch<React.SetStateAction<ThemeMode>>;
  // CTF 工作台全局密钥：带 key 参数的操作在私有值为空时自动回退到它（批次 M）。
  globalSecret: string;
  setGlobalSecret: React.Dispatch<React.SetStateAction<string>>;
}

export const StaticDataContext = createContext<StaticDataContextType | null>(null);
export const LanguageContext = createContext<LanguageContextType | null>(null);
export const NavContext = createContext<NavContextType | null>(null);
export const SearchContext = createContext<SearchContextType | null>(null);
export const SessionContext = createContext<SessionContextType | null>(null);

function useContextOrThrow<T>(context: React.Context<T | null>, hookName: string): T {
  const value = useContext(context);
  if (!value) {
    throw new Error(`${hookName} must be used within its Provider`);
  }
  return value;
}

export const useStaticData = () => useContextOrThrow(StaticDataContext, 'useStaticData');
export const useLanguage = () => useContextOrThrow(LanguageContext, 'useLanguage');
export const useNav = () => useContextOrThrow(NavContext, 'useNav');
export const useSearch = () => useContextOrThrow(SearchContext, 'useSearch');
export const useSession = () => useContextOrThrow(SessionContext, 'useSession');

// 旧聚合形状：未迁移组件的渐进迁移兼容层。聚合对象订阅全部 5 个 context，
// 任何一个域变更都会触发重渲染——迁移到上面的细分 hook 才能获得精准重渲染。
export interface AppContextType extends
  StaticDataContextType,
  LanguageContextType,
  NavContextType,
  SearchContextType,
  SessionContextType {}

export const useAppContext = (): AppContextType => {
  const staticData = useStaticData();
  const language = useLanguage();
  const nav = useNav();
  const search = useSearch();
  const session = useSession();
  return useMemo(
    () => ({ ...staticData, ...language, ...nav, ...search, ...session }),
    [staticData, language, nav, search, session],
  );
};
