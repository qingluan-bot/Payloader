import { lazy, Suspense, useEffect, useMemo, useRef } from 'react';
import type { ReactNode } from 'react';
import { vulnTypeLabel, severityLabel } from '../utils/exploit-labels';
import { useLanguage, useNav, useSearch, useStaticData } from '../appContext';
import { getText } from '../i18n';
import { openProtectedExternalLink } from '../protectedLinks';
import PayloadDetail from './PayloadDetail';
import ToolDetail from './ToolDetail';
import ListState, { WorkbenchEmpty } from './ListState';
import { ExploitCorpusDetail, ExploitDetail, ExploitLibrary } from './ExploitDetail';
import { exploitTreeTypeMap } from '../utils/exploit-tree';
import { stripLeadingPictographs } from '../utils/stripPictographs';
import ClientDownloads from './ClientDownloads';
import SimpleTextDetail from './SimpleTextDetail';
import MobileCategoryBar from './MobileCategoryBar';
import MobileCategoryList from './MobileCategoryList';
import MobileMoreView from './MobileMoreView';
import { MOBILE_BREAKPOINT, useMediaQuery } from './useMediaQuery';
import type { PublicClientBuildInfo } from '../types';
import '../styles/main-content.css';

const LazyCtfToolkit = lazy(() => import('./CtfToolkit'));

// E-20 页脚元数据：package.json 无前端注入通道（vite 无 define、无版本 API，clientBuildInfo
// 是下载页构建产物元数据而非应用版本），按约定落地静态常量，发版时与 package.json 同步更新
const APP_VERSION = 'v2.0.2';

interface MainContentProps {
  clientBuildInfo: PublicClientBuildInfo | null;
  /** 编解码工作台内容（移动端「更多」页内嵌用） */
  encodingTools?: ReactNode;
  onOpenClientDownloads?: () => void;
  /** 打包离线客户端内不显示下载入口（与 Header 同源：App 的 !isPackagedOfflineClient） */
  showClientDownloads?: boolean;
}

function MainContent({ clientBuildInfo, encodingTools, onOpenClientDownloads, showClientDownloads = true }: MainContentProps) {
  const {
    selectedPayloadId,
    selectedToolId,
    selectedExploitId,
    selectedExploitTypeId,
    setSelectedPayloadId,
    setSelectedToolId,
    setSelectedExploitId,
    setSelectedExploitTypeId,
    activeTab,
    activeView,
    setActiveView,
    mobileCategoryId,
  } = useNav();
  const { dataLoading, dataError, allPayloads, allToolCommands, allPayloadNavigation, allToolNavigation, allExploits, allExploitNavigation, settings } = useStaticData();
  // CTF 模块管理员开关（批次 TG）：关闭时不渲染 CtfToolkit，回落常规内容
  const ctfEnabled = settings.ctfEnabled !== false;
  const { deferredSearchQuery, searchMatches, setSearchQuery } = useSearch();
  const { language } = useLanguage();
  const isMobile = useMediaQuery(MOBILE_BREAKPOINT);
  // 移动视图栈滚动记忆（reviewer P1）：两 pane 共享滚动容器（.main-content，html/body 在
  // 窄屏断点 overflow:hidden），开详情存位归零、返回恢复，否则长列表开详情停在原偏移的
  // 空白区、返回后列表停在无关位置
  const prevExploitIdRef = useRef<string | null>(null);
  const exploitListScrollRef = useRef(0);

  useEffect(() => {
    if (!isMobile) return;
    const scroller = document.querySelector<HTMLElement>('.main-content');
    if (!scroller) return;
    const prev = prevExploitIdRef.current;
    prevExploitIdRef.current = selectedExploitId;
    if (!prev && selectedExploitId) {
      scroller.scrollTop = 0;
    } else if (prev && !selectedExploitId) {
      // 列表 pane 从 visibility:hidden 切回后布局高度要等重排才完整，同步恢复会被 clamp；
      // rAF 受 React 渲染调度影响可能被推迟到大列表重绘之后（实测延迟秒级），用宏任务等
      // pane 可见后再恢复（同 Sidebar openCard「下一帧才可滚」坑位的变体）
      window.setTimeout(() => {
        scroller.scrollTop = exploitListScrollRef.current;
      }, 60);
    }
  }, [isMobile, selectedExploitId]);

  const query = deferredSearchQuery.trim();

  const payloadResults = useMemo(() => {
    if (!query) return [];
    return allPayloads
      .filter(payload => searchMatches.payloadIds.has(payload.id))
      // P1-2 列表投影：计数来自服务端派生字段（execution/wafBypass 不再随列表下发）
      .map(payload => ({
        payload,
        commandCount: payload.commandCount ?? 0,
        bypassCount: payload.bypassCount ?? 0,
      }))
      .slice(0, 80);
  }, [allPayloads, query, searchMatches.payloadIds]);

  const toolResults = useMemo(() => {
    if (!query) return [];
    return allToolCommands
      .filter(tool => searchMatches.toolIds.has(tool.id))
      .slice(0, 80);
  }, [allToolCommands, query, searchMatches.toolIds]);

  const exploitResults = useMemo(() => {
    if (!query) return [];
    return allExploits
      .filter(exploit => searchMatches.exploitIds.has(exploit.id))
      .slice(0, 80);
  }, [allExploits, query, searchMatches.exploitIds]);

  const homeActions = useMemo(() => {
    const findDestination = (item: (typeof allPayloadNavigation)[number]): { payloadId?: string; toolId?: string; exploitId?: string } | null => {
      if (item.payloadId) return { payloadId: item.payloadId };
      if (item.toolId) return { toolId: item.toolId };
      if (item.exploitId) return { exploitId: item.exploitId };
      for (const child of item.children || []) {
        const destination = findDestination(child);
        if (destination) return destination;
      }
      return null;
    };

    const navigation = activeTab === 'payloads'
      ? allPayloadNavigation
      : activeTab === 'tools'
        ? allToolNavigation
        : allExploitNavigation;
    return navigation
      .map(item => ({ label: stripLeadingPictographs(getText(item.name, language)), destination: findDestination(item) }))
      .filter(action => action.destination)
      .slice(0, 8);
  }, [activeTab, allPayloadNavigation, allToolNavigation, allExploitNavigation, language]);

  const openPayload = (payloadId: string) => {
    setActiveView('workspace');
    setSelectedPayloadId(payloadId);
    setSelectedToolId(null);
    setSelectedExploitId(null);
    setSelectedExploitTypeId(null);
    setSearchQuery('');
  };

  const openTool = (toolId: string) => {
    setActiveView('workspace');
    const tool = allToolCommands.find(candidate => candidate.id === toolId);
    if (tool?.externalUrl && openProtectedExternalLink(tool.externalUrl)) {
      setSearchQuery('');
      return;
    }
    setSelectedToolId(toolId);
    setSelectedPayloadId(null);
    setSelectedExploitId(null);
    setSelectedExploitTypeId(null);
    setSearchQuery('');
  };

  const openExploit = (exploitId: string) => {
    // 滚动记忆在用户手势同步点存入：effect 时机 DOM 可能已被详情挂载后的 clamp 改写
    if (isMobile) {
      const scroller = document.querySelector<HTMLElement>('.main-content');
      if (scroller) exploitListScrollRef.current = scroller.scrollTop;
    }
    setActiveView('workspace');
    setSelectedExploitId(exploitId);
    setSelectedPayloadId(null);
    setSelectedToolId(null);
    setSearchQuery('');
  };

  const openHomeAction = (destination: { payloadId?: string; toolId?: string; exploitId?: string }) => {
    if (destination.payloadId) openPayload(destination.payloadId);
    else if (destination.toolId) openTool(destination.toolId);
    else if (destination.exploitId) openExploit(destination.exploitId);
  };

  // 工作台式空态（D-6/A7）chip/主按钮的 onSelect 闭包在 JSX 事件位构造（不放渲染期
  // useMemo：openHomeAction → openExploit 会写滚动记忆 ref，react-hooks/refs 会把
  // 渲染期构建的闭包链判成 ref 访问）
  const workbenchChipActions = (labels: typeof homeActions) =>
    labels.map(action => ({ label: action.label, onSelect: () => openHomeAction(action.destination!) }));

  const renderSearchResults = () => {
    // CTF 标签页下全局搜索沿用 Payload 库结果（工具命令属于渗透工作流）。
    const resultMode = activeTab === 'tools' ? 'tools' : activeTab === 'exploits' ? 'exploits' : 'payloads';
    const resultCount = resultMode === 'tools'
      ? toolResults.length
      : resultMode === 'exploits' ? exploitResults.length : payloadResults.length;
    const title = language === 'zh'
      ? `搜索结果：${deferredSearchQuery.trim()}`
      : `Search results: ${deferredSearchQuery.trim()}`;
    const hint = language === 'zh'
      ? '点开结果后即可查看可复制列表。'
      : 'Open a result to view the copyable list.';

    return (
      <div className="search-results-view">
        <div className="search-results-head">
          <div>
            <h2>{title}</h2>
            <p>{resultCount ? hint : (language === 'zh' ? '没有匹配的数据，换个关键词试试。' : 'No matches. Try another keyword.')}</p>
          </div>
          <button type="button" onClick={() => setSearchQuery('')}>{language === 'zh' ? '清除搜索' : 'Clear'}</button>
        </div>

        {resultCount ? (
          <div className="result-list">
            {resultMode === 'payloads' && payloadResults.map(result => result && (
              <button key={result.payload.id} type="button" className="result-item" onClick={() => openPayload(result.payload.id)}>
                <span className="result-title">{getText(result.payload.name, language)}</span>
                <span className="result-desc">{getText(result.payload.description, language)}</span>
                <span className="result-meta">
                  {getText(result.payload.category, language)}
                  <span>{language === 'zh' ? `${result.commandCount} 条标准` : `${result.commandCount} standard`}</span>
                  {result.bypassCount ? <span>{language === 'zh' ? `${result.bypassCount} 条绕过` : `${result.bypassCount} bypass`}</span> : null}
                </span>
              </button>
            ))}
            {resultMode === 'tools' && toolResults.map(tool => (
              <button key={tool.id} type="button" className="result-item" onClick={() => openTool(tool.id)}>
                <span className="result-title">{getText(tool.name, language)}</span>
                <span className="result-desc">{getText(tool.description, language)}</span>
                <span className="result-meta">
                  {getText(tool.category, language)}
                  <span>{tool.externalUrl ? (language === 'zh' ? '外链跳转' : 'External link') : (language === 'zh' ? `${tool.commands.length} 条命令` : `${tool.commands.length} commands`)}</span>
                </span>
              </button>
            ))}
            {resultMode === 'exploits' && exploitResults.map(exploit => (
              <button key={exploit.id} type="button" className="result-item" onClick={() => openExploit(exploit.id)}>
                <span className="result-title">{exploit.name}</span>
                <span className="result-desc">{exploit.description}</span>
                <span className="result-meta">
                  <span className="result-vid">{exploit.vulnerabilityIds.map(vid => vid.value).join(' / ') || exploit.id}</span>
                  <span>{vulnTypeLabel(exploit.vulnType, language)}</span>
                  <span>{severityLabel(exploit.severity, language)}</span>
                </span>
              </button>
            ))}
          </div>
        ) : (
          <ListState
            variant="empty"
            title={language === 'zh' ? '没有匹配结果' : 'No matches'}
            description={language === 'zh' ? '可以搜索漏洞名、漏洞编号、Payload 片段、命令、工具名或标签。' : 'Search by name, CVE ID, payload snippet, command, tool, or tag.'}
          />
        )}
      </div>
    );
  };

  const renderContent = () => {
    if (dataLoading) {
      return (
        <div className="empty-state" role="status" aria-live="polite">
          <h2>正在加载数据</h2>
          <p>Payloader 正在读取本地 SQLite 数据库</p>
        </div>
      );
    }

    if (dataError) {
      return (
        <div className="empty-state" role="alert">
          <h2>数据加载失败</h2>
          <p>{dataError}</p>
        </div>
      );
    }

    // 搜索优先于「更多」页：移动端顶栏搜索是常驻入口，键入即出结果（reviewer P1）
    if (query) {
      return renderSearchResults();
    }

    // 移动端「更多」页（MobileNav 第四项）：isMobile 门控——跨断点 resize 后 activeView='more'
    // 可能残留，桌面不得渲染移动专用视图（自然回落 workspace 各分支）
    if (activeView === 'more' && isMobile) {
      return (
        <MobileMoreView
          encodingTools={encodingTools}
          showClientDownloads={showClientDownloads}
          onOpenClientDownloads={onOpenClientDownloads ?? (() => { })}
          clientBuildInfo={clientBuildInfo}
        />
      );
    }

    if (activeView === 'clientDownloads') {
      return <ClientDownloads clientBuildInfo={clientBuildInfo} />;
    }

    if (activeTab === 'ctf' && !query && ctfEnabled) {
      return (
        <Suspense fallback={<div className="lazy-loading" role="status" aria-live="polite">正在加载 CTF 解题工具箱...</div>}>
          <LazyCtfToolkit />
        </Suspense>
      );
    }

    if (activeTab === 'exploits') {
      // 移动视图栈（M3）：列表与详情并存挂载（grid 同格叠放 + visibility/inert 切换），
      // 返回时列表滚动位置与筛选状态零丢失；桌面保持条件渲染（列表卸载）不变。
      if (isMobile) {
        let detailPane: ReactNode = null;
        if (selectedExploitId) {
          // 直达支持 EXP ID 与漏洞编号（CVE-2021-44228 / 50592 等，大小写不敏感），
          // 与公开 API /api/exploits/:id 的解析语义一致；精选层未命中回退聚合层按需拉取
          const needle = selectedExploitId.toLowerCase();
          const exploit = allExploits.find(item => item.id === selectedExploitId)
            ?? allExploits.find(item => item.vulnerabilityIds.some(vid => vid.value.toLowerCase() === needle));
          detailPane = exploit
            ? <ExploitDetail key={exploit.id} exploit={exploit} />
            : (
              <ExploitCorpusDetail
                key={selectedExploitId}
                identifier={selectedExploitId}
                onBack={() => setSelectedExploitId(null)}
              />
            );
        }
        // 左树类型节点分类浏览：锁定漏洞类型的全量分页列表（key remount 使 type 初值生效）
        const typeMapping = selectedExploitTypeId ? exploitTreeTypeMap[selectedExploitTypeId] : undefined;
        const listPane = typeMapping
          ? (
            <ExploitLibrary
              key={selectedExploitTypeId}
              lockedType={typeMapping}
              exploits={allExploits}
              onOpen={openExploit}
              homeActions={[]}
              onOpenHomeAction={() => { }}
            />
          )
          : (
            <ExploitLibrary
              exploits={allExploits}
              onOpen={openExploit}
              homeActions={homeActions}
              onOpenHomeAction={openHomeAction}
            />
          );
        return (
          <div className="mobile-panes">
            <div
              className={`mobile-pane${selectedExploitId ? ' pane-hidden' : ''}`}
              inert={selectedExploitId ? true : undefined}
            >
              {listPane}
            </div>
            {detailPane && <div className="mobile-pane mobile-pane-detail">{detailPane}</div>}
          </div>
        );
      }
      if (selectedExploitId) {
        // 直达支持 EXP ID 与漏洞编号（CVE-2021-44228 / 50592 等，大小写不敏感），
        // 与公开 API /api/exploits/:id 的解析语义一致；精选层未命中回退聚合层按需拉取
        const needle = selectedExploitId.toLowerCase();
        const exploit = allExploits.find(item => item.id === selectedExploitId)
          ?? allExploits.find(item => item.vulnerabilityIds.some(vid => vid.value.toLowerCase() === needle));
        if (exploit) return <ExploitDetail key={exploit.id} exploit={exploit} />;
        return (
          <ExploitCorpusDetail
            key={selectedExploitId}
            identifier={selectedExploitId}
            onBack={() => setSelectedExploitId(null)}
          />
        );
      }
      // 左树类型节点分类浏览：锁定漏洞类型的全量分页列表（key remount 使 type 初值生效）
      const typeMapping = selectedExploitTypeId ? exploitTreeTypeMap[selectedExploitTypeId] : undefined;
      if (typeMapping) {
        return (
          <ExploitLibrary
            key={selectedExploitTypeId}
            lockedType={typeMapping}
            exploits={allExploits}
            onOpen={openExploit}
            homeActions={[]}
            onOpenHomeAction={() => { }}
          />
        );
      }
      return (
        <ExploitLibrary
          exploits={allExploits}
          onOpen={openExploit}
          homeActions={homeActions}
          onOpenHomeAction={openHomeAction}
        />
      );
    }

    if (activeTab === 'payloads') {
      if (selectedPayloadId) {
        const p = allPayloads.find(x => x.id === selectedPayloadId);
        const cat = p ? (typeof p.category === 'string' ? p.category : p.category.zh) : '';
        if (cat === '自定义') return <SimpleTextDetail payloadId={selectedPayloadId} />;
        // key 强制重挂：payloadId 变化时详情组件的局部状态（详情缓存/骨架态）自然清零
        return <PayloadDetail key={selectedPayloadId} payloadId={selectedPayloadId} />;
      }
      // 移动端分类浏览：分类 sheet 选中分类后渲染该分类条目列表（M2）
      if (isMobile && mobileCategoryId) {
        return <MobileCategoryList categoryId={mobileCategoryId} onOpenPayload={openPayload} onOpenTool={openTool} />;
      }
      return (
        <WorkbenchEmpty
          title={language === 'zh' ? '选择攻击类型' : 'Select an attack type'}
          description={language === 'zh'
            ? '左侧分类树按攻击场景组织 Payload，选中分类或条目即可查看可复制的执行内容与绕过变体。'
            : 'The category tree on the left organizes payloads by attack scenario; pick one to view copyable commands and bypass variants.'}
          primaryLabel={homeActions[0]
            ? (language === 'zh' ? `从「${homeActions[0].label}」开始` : `Start with ${homeActions[0].label}`)
            : undefined}
          onPrimary={homeActions[0] ? () => openHomeAction(homeActions[0].destination!) : undefined}
          actions={workbenchChipActions(homeActions)}
          actionsLabel={language === 'zh' ? '常用分类' : 'Common categories'}
        />
      );
    }

    if (selectedToolId) {
      return <ToolDetail toolId={selectedToolId} />;
    }

    // 移动端分类浏览（工具域 fallback）：payload 分支已在上方 return，此处 activeTab
    // 只剩 tools/ctf——hash 直切 tab 不走 switchTab，mobileCategoryId 可能残留，用
    // tab 条件防残留态污染 CTF 等其它 tab
    if (isMobile && mobileCategoryId && activeTab === 'tools') {
      return <MobileCategoryList categoryId={mobileCategoryId} onOpenPayload={openPayload} onOpenTool={openTool} />;
    }

    // custom payload selected while on tools tab
    if (selectedPayloadId) {
      const p = allPayloads.find(x => x.id === selectedPayloadId);
      const cat = p ? (typeof p.category === 'string' ? p.category : p.category.zh) : '';
      if (cat === '自定义') return <SimpleTextDetail payloadId={selectedPayloadId} />;
    }

    return (
      <WorkbenchEmpty
        title={language === 'zh' ? '选择工具' : 'Select a tool'}
        description={language === 'zh'
          ? '左侧分类树收录常用命令行工具，选中分类或条目即可查看安装方法与可复制命令。'
          : 'The category tree on the left lists common CLI tools; pick one to view installation steps and copyable commands.'}
        primaryLabel={homeActions[0]
          ? (language === 'zh' ? `从「${homeActions[0].label}」开始` : `Start with ${homeActions[0].label}`)
          : undefined}
        onPrimary={homeActions[0] ? () => openHomeAction(homeActions[0].destination!) : undefined}
        actions={workbenchChipActions(homeActions)}
        actionsLabel={language === 'zh' ? '常用分类' : 'Common categories'}
      />
    );
  };

  // 移动端列表视图顶部「当前分类」横条：详情全屏/搜索结果/CTF/更多页/下载页不显示
  const showCategoryBar = isMobile
    && activeView === 'workspace'
    && activeTab !== 'ctf'
    && !query
    && !selectedPayloadId
    && !selectedToolId
    && !selectedExploitId;

  return (
    <main className="main-content" id="main-content" tabIndex={-1}>
      {showCategoryBar && <MobileCategoryBar />}
      {renderContent()}
      <footer className="main-footer">
        <span className="main-footer-version">Payloader {APP_VERSION}</span>
        <span>{language === 'zh' ? '仅供授权安全测试与学习使用' : 'For authorized security testing and learning only'}</span>
      </footer>
    </main>
  );
}

export default MainContent;
