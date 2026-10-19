import { memo, useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import type { ChangeEvent, FocusEvent, KeyboardEvent, ReactNode } from 'react';
import { useLanguage, useNav, useSearch, useStaticData } from '../appContext';
import { t, getText } from '../i18n';
import { openProtectedExternalLink } from '../protectedLinks';
import { buildSearchIndex, matchSearchIndex } from '../searchIndex';
import { severityLabel, vulnTypeLabel } from '../utils/exploit-labels';
import { MOBILE_BREAKPOINT, useMediaQuery } from './useMediaQuery';
import { useDismissable } from './useDismissable';
import { Icon } from './Icon';

// 下拉预览防抖窗口与每组截断条数（walkthrough E-07：防抖下拉预览 + 整页兜底）
const PREVIEW_DEBOUNCE_MS = 200;
const PREVIEW_GROUP_LIMIT = 5;

type PreviewKind = 'payload' | 'tool' | 'exploit' | 'view-all';

interface PreviewRow {
  kind: PreviewKind;
  id: string;
  title: string;
  meta: string;
}

// 命中段高亮：标题/元信息中首个查询词命中加 accent（整页搜索无高亮实现，下拉侧内建轻量版）
function renderHit(text: string, normalizedQuery: string): ReactNode {
  const query = normalizedQuery.trim().toLowerCase();
  if (!query) return text;
  const hitAt = text.toLowerCase().indexOf(query);
  if (hitAt < 0) return text;
  return (
    <>
      {text.slice(0, hitAt)}
      <span className="hs-hit">{text.slice(hitAt, hitAt + query.length)}</span>
      {text.slice(hitAt + query.length)}
    </>
  );
}

function HeaderSearch() {
  const { language } = useLanguage();
  const isMobile = useMediaQuery(MOBILE_BREAKPOINT);
  const {
    setActiveView,
    setSelectedPayloadId,
    setSelectedToolId,
    setSelectedExploitId,
    setSelectedExploitTypeId,
  } = useNav();
  // searchQuery 语义收敛为「已提交的整页搜索词」：仅“查看全部/回车”显式提交才写入，
  // 键入过程只进本地 draft，浏览上下文（tab/选中/滚动）不再被顶栏输入打断。
  const { searchQuery, setSearchQuery, payloadCommandCorpus } = useSearch();
  const { allPayloads, allToolCommands, allExploits } = useStaticData();

  // 移动端顶栏收窄：搜索默认收起为图标按钮，点开全宽输入；失焦且无关键词时自动收起。
  const [mobileExpanded, setMobileExpanded] = useState(false);
  // draft = 键入中的本地草稿；null 表示无在途编辑，回显全局已提交词（整页视图点开详情/
  // 页内“清除搜索”把 searchQuery 清空时，输入框经同一表达式自动清零，无 effect 同步路径）。
  const [draft, setDraft] = useState<string | null>(null);
  const inputValue = draft ?? searchQuery;
  const expanded = !isMobile || mobileExpanded || inputValue.length > 0;

  const [previewQuery, setPreviewQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [highlightIndex, setHighlightIndex] = useState(-1);

  const inputRef = useRef<HTMLInputElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<number | null>(null);
  const listboxId = useId();

  // 与整页搜索共用同一数据源函数（buildSearchIndex/matchSearchIndex，见 searchIndex.ts），
  // 仅按静态数据/语言重建，键入路径零重建。payloadCommandCorpus 为 P1-2 延迟语料，
  // 到达后下拉预览同样覆盖命令文本检索（与整页搜索同口径）。
  const previewIndex = useMemo(
    () => buildSearchIndex(allPayloads, allToolCommands, allExploits, language, payloadCommandCorpus),
    [allPayloads, allToolCommands, allExploits, language, payloadCommandCorpus],
  );
  const previewMatches = useMemo(
    () => matchSearchIndex(previewIndex, previewQuery),
    [previewIndex, previewQuery],
  );

  const normalizedPreview = previewQuery.trim().toLowerCase();
  const payloadRows = useMemo(() => (
    normalizedPreview
      ? allPayloads
        .filter(payload => previewMatches.payloadIds.has(payload.id))
        .slice(0, PREVIEW_GROUP_LIMIT)
        .map(payload => ({
          kind: 'payload' as const,
          id: payload.id,
          title: getText(payload.name, language),
          meta: getText(payload.category, language),
        }))
      : []
  ), [allPayloads, previewMatches.payloadIds, normalizedPreview, language]);
  const toolRows = useMemo(() => (
    normalizedPreview
      ? allToolCommands
        .filter(tool => previewMatches.toolIds.has(tool.id))
        .slice(0, PREVIEW_GROUP_LIMIT)
        .map(tool => ({
          kind: 'tool' as const,
          id: tool.id,
          title: getText(tool.name, language),
          meta: getText(tool.category, language),
        }))
      : []
  ), [allToolCommands, previewMatches.toolIds, normalizedPreview, language]);
  const exploitRows = useMemo(() => (
    normalizedPreview
      ? allExploits
        .filter(exploit => previewMatches.exploitIds.has(exploit.id))
        .slice(0, PREVIEW_GROUP_LIMIT)
        .map(exploit => ({
          kind: 'exploit' as const,
          id: exploit.id,
          title: exploit.name,
          meta: `${vulnTypeLabel(exploit.vulnType, language)} · ${severityLabel(exploit.severity, language)}`,
        }))
      : []
  ), [allExploits, previewMatches.exploitIds, normalizedPreview, language]);

  const totalMatches = previewMatches.payloadIds.size
    + previewMatches.toolIds.size
    + previewMatches.exploitIds.size;

  // 键盘平面序（跨组连续）：payload → tool → exploit → 「查看全部」兜底行
  const optionRows = useMemo<PreviewRow[]>(() => {
    const rows: PreviewRow[] = [...payloadRows, ...toolRows, ...exploitRows];
    if (totalMatches > 0) {
      rows.push({
        kind: 'view-all',
        id: '',
        title: language === 'zh' ? `查看全部 ${totalMatches} 条结果` : `View all ${totalMatches} results`,
        meta: '',
      });
    }
    return rows;
  }, [exploitRows, language, payloadRows, toolRows, totalMatches]);

  const clearDebounce = useCallback(() => {
    if (debounceRef.current !== null) {
      window.clearTimeout(debounceRef.current);
      debounceRef.current = null;
    }
  }, []);

  useEffect(() => () => clearDebounce(), [clearDebounce]);

  // 移动端点图标展开后直接聚焦输入；focus 非 setState，不触 set-state-in-effect 规则。
  useEffect(() => {
    if (isMobile && mobileExpanded) inputRef.current?.focus();
  }, [isMobile, mobileExpanded]);

  useDismissable({
    enabled: open,
    containerRef: boxRef,
    buttonRef: inputRef,
    onClose: () => setOpen(false),
    getEscapeFocusTarget: () => null,
  });

  // 高亮项跟随滚动（仅 DOM 命令，无 setState，不涉 effect 同步路径）
  useEffect(() => {
    if (highlightIndex < 0 || !open) return;
    document.getElementById(`${listboxId}-opt-${highlightIndex}`)?.scrollIntoView({ block: 'nearest' });
  }, [highlightIndex, open, listboxId]);

  const openPreviewNow = useCallback((text: string) => {
    clearDebounce();
    setPreviewQuery(text);
    setHighlightIndex(-1);
    setOpen(true);
  }, [clearDebounce]);

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    const text = event.target.value;
    setDraft(text);
    // 快速连续输入防闪抖：防抖合并 + 取消上一次未决查询；清空立即收起
    clearDebounce();
    if (!text.trim()) {
      setPreviewQuery('');
      setOpen(false);
      setHighlightIndex(-1);
      return;
    }
    debounceRef.current = window.setTimeout(() => {
      debounceRef.current = null;
      setPreviewQuery(text);
      setHighlightIndex(-1);
      setOpen(true);
    }, PREVIEW_DEBOUNCE_MS);
  };

  // 整页搜索兜底入口：显式提交才切换主内容视图（行为与旧搜索入口一致，回到工作区再渲染结果）
  const commitFullSearch = useCallback((rawText: string) => {
    const query = rawText.trim();
    clearDebounce();
    setOpen(false);
    setHighlightIndex(-1);
    setDraft(null);
    if (!query) return;
    setActiveView('workspace');
    setSearchQuery(query);
  }, [clearDebounce, setActiveView, setSearchQuery]);

  const openRow = useCallback((row: PreviewRow) => {
    clearDebounce();
    setOpen(false);
    setHighlightIndex(-1);
    setDraft(null);
    setActiveView('workspace');
    if (row.kind === 'payload') {
      setSelectedPayloadId(row.id);
      setSelectedToolId(null);
      setSelectedExploitId(null);
      setSelectedExploitTypeId(null);
    } else if (row.kind === 'tool') {
      // 外链工具与整页视图 openTool 同语义：跳外部并清搜索词
      const tool = allToolCommands.find(candidate => candidate.id === row.id);
      if (tool?.externalUrl && openProtectedExternalLink(tool.externalUrl)) {
        setSearchQuery('');
        return;
      }
      setSelectedToolId(row.id);
      setSelectedPayloadId(null);
      setSelectedExploitId(null);
      setSelectedExploitTypeId(null);
    } else if (row.kind === 'exploit') {
      setSelectedExploitId(row.id);
      setSelectedPayloadId(null);
      setSelectedToolId(null);
    }
    setSearchQuery('');
  }, [allToolCommands, clearDebounce, setActiveView, setSearchQuery, setSelectedExploitId, setSelectedExploitTypeId, setSelectedPayloadId, setSelectedToolId]);

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      if (!open) {
        if (inputValue.trim()) openPreviewNow(inputValue);
        return;
      }
      setHighlightIndex(index => Math.min(index + 1, optionRows.length - 1));
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      if (open) setHighlightIndex(index => Math.max(index - 1, -1));
    } else if (event.key === 'Enter') {
      event.preventDefault();
      const row = open ? optionRows[highlightIndex] : undefined;
      if (row && row.kind !== 'view-all') openRow(row);
      else commitFullSearch(inputValue);
    } else if (event.key === 'Escape' && open) {
      // Esc：关下拉并清焦点（外部 Esc 由 useDismissable 兜底关闭）
      event.preventDefault();
      event.stopPropagation();
      clearDebounce();
      setOpen(false);
      inputRef.current?.blur();
    }
  };

  const handleFocus = () => {
    // 已有内容时聚焦重开预览（与 GitHub 顶栏一致）；空输入不下拉
    if (inputValue.trim()) openPreviewNow(inputValue);
  };

  const handleBlur = (event: FocusEvent<HTMLInputElement>) => {
    if (isMobile && !inputValue) setMobileExpanded(false);
    // 焦点仍在搜索框内（如点 ×/下拉已被 mousedown preventDefault 保护）不收起
    if (boxRef.current?.contains(event.relatedTarget as Node | null)) return;
    // 取消在途防抖：否则失焦后 200ms 定时器仍会把下拉弹回无焦点状态
    clearDebounce();
    setOpen(false);
  };

  const handleClear = () => {
    clearDebounce();
    setPreviewQuery('');
    setOpen(false);
    setHighlightIndex(-1);
    setDraft(null);
    if (searchQuery) setSearchQuery('');
  };

  const renderOption = (row: PreviewRow, index: number) => (
    <div
      key={`${row.kind}:${row.id || 'all'}`}
      id={`${listboxId}-opt-${index}`}
      role="option"
      aria-selected={index === highlightIndex}
      className={`hs-option${row.kind === 'view-all' ? ' hs-option-all' : ''}`}
      onClick={() => {
        if (row.kind === 'view-all') commitFullSearch(inputValue);
        else openRow(row);
      }}
    >
      {row.kind === 'view-all' ? (
        <>
          <span className="hs-option-label">{row.title}</span>
          <Icon name="arrow-right" size={14} className="hs-option-go" />
        </>
      ) : (
        <>
          <span className="hs-option-label">{renderHit(row.title, normalizedPreview)}</span>
          <span className="hs-option-meta">{renderHit(row.meta, normalizedPreview)}</span>
        </>
      )}
    </div>
  );

  if (!expanded) {
    return (
      <button
        type="button"
        className="search-box search-collapsed"
        aria-label={t('header.searchPlaceholder', language)}
        onClick={() => setMobileExpanded(true)}
      >
        <span className="search-icon" aria-hidden="true"><Icon name="search" size={16} /></span>
      </button>
    );
  }

  const payloadOffset = 0;
  const toolOffset = payloadRows.length;
  const exploitOffset = toolOffset + toolRows.length;
  const viewAllIndex = exploitOffset + exploitRows.length;

  return (
    <div className="search-box" role="search" ref={boxRef}>
      <span className="search-icon" aria-hidden="true"><Icon name="search" size={16} /></span>
      <input
        ref={inputRef}
        type="search"
        name="content-search"
        className="search-input"
        placeholder={t('header.searchPlaceholder', language)}
        aria-label={t('header.searchPlaceholder', language)}
        value={inputValue}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        onFocus={handleFocus}
        onBlur={handleBlur}
        role="combobox"
        aria-expanded={open}
        aria-controls={open ? listboxId : undefined}
        aria-autocomplete="list"
        aria-activedescendant={open && highlightIndex >= 0 ? `${listboxId}-opt-${highlightIndex}` : undefined}
      />
      {inputValue && (
        <button
          type="button"
          className="search-clear"
          onClick={handleClear}
          aria-label={language === 'zh' ? '清除搜索' : 'Clear search'}
        >
          <Icon name="x" size={14} />
        </button>
      )}
      {open && (
        <div
          className="hs-panel"
          id={listboxId}
          role="listbox"
          aria-label={language === 'zh' ? '搜索建议' : 'Search suggestions'}
          onMouseDown={event => event.preventDefault()}
        >
          {totalMatches === 0 ? (
            <div className="hs-empty" role="presentation">
              {language === 'zh' ? '没有匹配结果' : 'No matches'}
            </div>
          ) : (
            <>
              {payloadRows.length > 0 && (
                <>
                  <div className="hs-group" role="presentation">{language === 'zh' ? 'Payload' : 'payloads'}</div>
                  {payloadRows.map((row, index) => renderOption(row, payloadOffset + index))}
                </>
              )}
              {toolRows.length > 0 && (
                <>
                  <div className="hs-group" role="presentation">{language === 'zh' ? '工具命令' : 'tools'}</div>
                  {toolRows.map((row, index) => renderOption(row, toolOffset + index))}
                </>
              )}
              {exploitRows.length > 0 && (
                <>
                  <div className="hs-group" role="presentation">{language === 'zh' ? 'EXP' : 'exploits'}</div>
                  {exploitRows.map((row, index) => renderOption(row, exploitOffset + index))}
                </>
              )}
              {renderOption(optionRows[viewAllIndex], viewAllIndex)}
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default memo(HeaderSearch);
