import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLanguage, useNav, useSearch, useStaticData } from '../appContext';
import { t, getText } from '../i18n';
import { openProtectedExternalLink } from '../protectedLinks';
import { groupDenseLeaves } from '../utils/navigationGrouping';
import { annotateExploitTree } from '../utils/exploit-tree';
import { stripLeadingPictographs } from '../utils/stripPictographs';
import { Icon } from './Icon';
import type { I18nText, NavItem } from '../types';

// 分类树本体（自 Sidebar 拆出）：桌面侧栏与移动端「分类选择」BottomSheet 共用同一棵树，
// TreeNode/键盘导航/搜索过滤/EXP 类型节点标注逻辑只有这一份。抽屉壳（inert/ESC）留在 Sidebar。

interface TreeNodeProps {
  item: NavItem;
  level: number;
  matchedIds: ReadonlySet<string>;
  forceExpand: boolean;
  isSelected: boolean;
  // 本节点子树内是否包含当前选中叶子：选择跨枝移动时祖先链借此感知并重渲染，
  // 未受影响子树在 memo 比较器处整体 bail（原始选中 id 只供递归计算，不进比较面）。
  branchSelected: boolean;
  onSelect: (item: NavItem) => void;
  isFirst?: boolean;
  onNavigate?: () => void;
  /** 分类选择模式（移动端分类 sheet）：点分类节点即回调选中（不再仅展开），叶子行为不变 */
  onCategoryPick?: (item: NavItem) => void;
  // 当前选中叶子的统一 id（payload/tool/exploit 任一）：比较器用它感知"同枝内移动选中"——
  // 该场景下祖先链 branchSelected 恒为 true、自身 isSelected 不变，没有它祖先会整体 bail。
  selectedLeafId: string | null;
  /** EXP 类型节点浏览态 id：命中则本节点高亮（分类入口） */
  selectedExploitTypeId?: string | null;
}

// 叶子统一 id：payload/tool/exploit 三类内容的叶子标记收敛为一个比较面
const leafIdOf = (item: NavItem): string => item.payloadId || item.toolId || item.exploitId || '';

// 递归判断子树是否包含选中叶子（Nav 数据为静态引用，按值比较即可）。
function subtreeContains(item: NavItem, selectedLeafId: string | null): boolean {
  if (selectedLeafId != null && leafIdOf(item) === selectedLeafId) return true;
  return Boolean(item.children?.some(child => subtreeContains(child, selectedLeafId)));
}

const visibleTreeItems = (tree: Element | null) => (
  tree
    ? Array.from(tree.querySelectorAll<HTMLButtonElement>('button[role="treeitem"]'))
        .filter(element => element.offsetParent !== null)
    : []
);

function handleTreeKeyDown(event: KeyboardEvent) {
  const current = event.target;
  if (!(current instanceof HTMLButtonElement) || current.getAttribute('role') !== 'treeitem') return;

  const items = visibleTreeItems(current.closest('[role="tree"]'));
  const currentIndex = items.indexOf(current);
  const focusAt = (index: number) => {
    if (!items.length) return;
    items[Math.max(0, Math.min(index, items.length - 1))]?.focus();
  };

  if (event.key === 'ArrowDown') {
    event.preventDefault();
    focusAt(currentIndex + 1);
  } else if (event.key === 'ArrowUp') {
    event.preventDefault();
    focusAt(currentIndex - 1);
  } else if (event.key === 'Home') {
    event.preventDefault();
    focusAt(0);
  } else if (event.key === 'End') {
    event.preventDefault();
    focusAt(items.length - 1);
  } else if (event.key === 'ArrowRight' && current.hasAttribute('aria-expanded')) {
    event.preventDefault();
    if (current.getAttribute('aria-expanded') === 'false') {
      current.click();
    } else {
      const childGroup = current.parentElement?.children[1];
      childGroup?.getElementsByTagName('button')[0]?.focus();
    }
  } else if (event.key === 'ArrowLeft') {
    if (current.getAttribute('aria-expanded') === 'true') {
      event.preventDefault();
      current.click();
      return;
    }
    const parentGroup = current.parentElement?.parentElement;
    const parentItem = parentGroup?.getAttribute('role') === 'group'
      ? parentGroup.parentElement?.children[0]
      : null;
    if (parentItem instanceof HTMLElement) {
      event.preventDefault();
      parentItem.focus();
    }
  }
}

const TreeNode = memo(function TreeNode({
  item,
  level,
  matchedIds,
  forceExpand,
  isSelected,
  onSelect,
  isFirst = false,
  onNavigate,
  onCategoryPick,
  selectedLeafId,
  selectedExploitTypeId = null,
}: TreeNodeProps) {
  // branchSelected 不解构：它是 memo 比较器的传播信号（见比较器），组件体无需读取。
  const [isExpanded, setIsExpanded] = useState(false);
  const { language } = useLanguage();

  const hasChildren = item.children && item.children.length > 0;
  // 叶子过多的层级插入虚拟分组节点（二级菜单），避免几十个条目平铺在一层。
  const displayChildren = useMemo(
    () => (hasChildren
      ? groupDenseLeaves(
        item,
        item.children!,
        item.children!.some(child => child.payloadId) ? 'payload' : 'tool',
      )
      : []),
    [item, hasChildren],
  );
  const isMatched = matchedIds.has(leafIdOf(item));
  const hasMatchedDescendant = hasChildren && hasDescendantMatch(item, matchedIds);

  // Auto-expand when searching
  const effectiveExpanded = forceExpand ? (hasMatchedDescendant || isMatched) : isExpanded;

  if (forceExpand && !isMatched && !hasMatchedDescendant && !hasChildren) {
    return null;
  }

  if (forceExpand && hasChildren && !hasMatchedDescendant) {
    return null;
  }

  const handleClick = () => {
    if (hasChildren) {
      setIsExpanded(!isExpanded);
      // EXP 树类型节点（标注 vulnType）即分类入口：展开行为保留，同时进入该类型全量列表
      if (item.vulnType) onSelect(item);
      // 分类选择模式（移动端分类 sheet）：点分类节点即选中并关闭 sheet（展开态随之丢弃，无害）
      else onCategoryPick?.(item);
    } else {
      onSelect(item);
    }
  };

  return (
    <div className="tree-node" role="none">
      <button
        type="button"
        role="treeitem"
        aria-level={level + 1}
        aria-expanded={hasChildren ? effectiveExpanded : undefined}
        aria-selected={isSelected}
        aria-current={isSelected ? 'page' : undefined}
        tabIndex={isFirst ? 0 : -1}
        className={`tree-item ${isSelected ? 'selected' : ''} ${hasChildren ? 'has-children' : ''} ${isMatched && forceExpand ? 'search-match' : ''}`}
        style={{ paddingLeft: `${level * 16 + 12}px` }}
        onClick={handleClick}
      >
        {hasChildren && (
          <span className={`tree-expand-icon ${effectiveExpanded ? 'expanded' : ''}`} aria-hidden="true">
            <Icon name="chevron-right" size={12} />
          </span>
        )}
        {!hasChildren && <span className="tree-leaf-spacer" aria-hidden="true" />}
        <span className="tree-label">{stripLeadingPictographs(getText(item.name, language))}</span>
        {(item.payloadId || item.toolId || item.exploitId) && (
          <span
            className="tree-badge"
            title={item.payloadId ? (language === 'zh' ? 'Payload 条目' : 'Payload entry') : item.toolId ? (language === 'zh' ? '工具条目' : 'Tool entry') : (language === 'zh' ? 'EXP 条目' : 'Exploit entry')}
            aria-label={item.payloadId ? (language === 'zh' ? 'Payload 条目' : 'Payload entry') : item.toolId ? (language === 'zh' ? '工具条目' : 'Tool entry') : (language === 'zh' ? 'EXP 条目' : 'Exploit entry')}
          >
            {item.payloadId ? 'P' : item.toolId ? 'T' : 'E'}
          </span>
        )}
        {item.vulnType && (
          <span
            className="tree-badge tree-badge-type"
            title="查看该类型全部条目"
            aria-label="查看该类型全部条目"
            onClick={event => {
              // 徽标单一动作：仅进入该类型全量列表，不触发展开（展开是节点本体的行为）
              event.stopPropagation();
              onSelect(item);
            }}
          >
            全
          </span>
        )}
      </button>
      {hasChildren && effectiveExpanded && (
        <div className="tree-children" role="group">
          {displayChildren.map(child => (
            <TreeNode
              key={child.id}
              item={child}
              level={level + 1}
              matchedIds={matchedIds}
              forceExpand={forceExpand}
              isSelected={(leafIdOf(child) !== '' && leafIdOf(child) === selectedLeafId) || child.id === selectedExploitTypeId}
              branchSelected={subtreeContains(child, selectedLeafId)}
              onSelect={onSelect}
              onNavigate={onNavigate}
              onCategoryPick={onCategoryPick}
              selectedLeafId={selectedLeafId}
              selectedExploitTypeId={selectedExploitTypeId}
            />
          ))}
        </div>
      )}
    </div>
  );
}, (prev, next) =>
  // 规则一：选中叶子 id 变化且本枝（前或后）含选中 → 同枝内移动/进出，祖先链必须重渲染，
  // 否则新旧叶子的 isSelected 翻转永远无法下发（这是纯 branchSelected 方案的盲区）。
  // 规则二：其余情况按显示相关 props 逐项相等才 bail，未受影响子树整体跳过。
  !(prev.selectedLeafId !== next.selectedLeafId && (prev.branchSelected || next.branchSelected))
  && prev.item === next.item
  && prev.level === next.level
  && prev.matchedIds === next.matchedIds
  && prev.forceExpand === next.forceExpand
  && prev.isSelected === next.isSelected
  && prev.branchSelected === next.branchSelected
  && prev.onSelect === next.onSelect
  && prev.isFirst === next.isFirst
  && prev.onNavigate === next.onNavigate
  && prev.onCategoryPick === next.onCategoryPick
  && prev.selectedExploitTypeId === next.selectedExploitTypeId
);

function hasDescendantMatch(item: NavItem, matchedIds: ReadonlySet<string>): boolean {
  if (!item.children) return false;
  for (const child of item.children) {
    if (matchedIds.has(leafIdOf(child))) return true;
    if (hasDescendantMatch(child, matchedIds)) return true;
  }
  return false;
}

function isTreeItemVisible(item: NavItem, matchedIds: ReadonlySet<string>, isSearching: boolean): boolean {
  if (!isSearching) return true;
  const hasChildren = Boolean(item.children?.length);
  return hasChildren
    ? hasDescendantMatch(item, matchedIds)
    : matchedIds.has(leafIdOf(item));
}

function isCustomCategory(value: I18nText): boolean {
  if (typeof value === 'string') return value === '自定义' || value === 'Custom';
  return value.zh === '自定义' || value.en === 'Custom';
}

function CustomSection({ items, matchedIds, onNavigate, language, selectedLeafId, onSelect, isFirst = false }: { items: NavItem[]; matchedIds: ReadonlySet<string>; onNavigate?: () => void; language: string; selectedLeafId: string | null; onSelect: (item: NavItem) => void; isFirst?: boolean }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="tree-node" role="none">
      <button
        type="button"
        role="treeitem"
        aria-level={1}
        aria-expanded={expanded}
        aria-selected={false}
        tabIndex={isFirst ? 0 : -1}
        className="tree-item has-children"
        style={{ paddingLeft: '12px' }}
        onClick={() => setExpanded(current => !current)}
      >
        <span className={`tree-expand-icon ${expanded ? 'expanded' : ''}`} aria-hidden="true">▶</span>
        <span className="tree-label">{language === 'zh' ? '自定义文本' : 'Custom Text'}</span>
      </button>
      {expanded && (
        <div className="tree-children" role="group">
          {items.map(item => (
            <TreeNode
              key={item.id}
              item={item}
              level={1}
              matchedIds={matchedIds}
              forceExpand={false}
              isSelected={leafIdOf(item) !== '' && leafIdOf(item) === selectedLeafId}
              branchSelected={subtreeContains(item, selectedLeafId)}
              onSelect={onSelect}
              onNavigate={onNavigate}
              selectedLeafId={selectedLeafId}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export interface NavTreeProps {
  /** 叶子选中/外链跳转后的回调（抽屉关闭、sheet 关闭等） */
  onNavigate?: () => void;
  /** 分类选择模式（移动端分类 sheet）：点分类节点即回调 */
  onCategoryPick?: (item: NavItem) => void;
}

// 树内容 = 标题行（标题/清除分类/搜索计数）+ 树容器。两处挂载（桌面侧栏 + 移动 sheet）时
// 键盘导航监听为同一函数引用，addEventListener 天然去重，不会重复响应。
export function NavTree({ onNavigate, onCategoryPick }: NavTreeProps) {
  const {
    activeTab,
    selectedPayloadId,
    selectedToolId,
    selectedExploitId,
    selectedExploitTypeId,
    setSelectedPayloadId,
    setSelectedToolId,
    setSelectedExploitId,
    setSelectedExploitTypeId,
  } = useNav();
  const selectedLeafId = selectedPayloadId ?? selectedToolId ?? selectedExploitId;
  const { deferredSearchQuery, searchMatches } = useSearch();
  const { language } = useLanguage();
  const { allPayloads, allToolCommands, allPayloadNavigation, allToolNavigation, allExploitNavigation } = useStaticData();
  // EXP 树类型节点标注（前端注入，数据源不变）：类型层节点即全库分类入口
  const annotatedExploitNavigation = useMemo(
    () => (activeTab === 'exploits' ? annotateExploitTree(allExploitNavigation) : allExploitNavigation),
    [activeTab, allExploitNavigation],
  );

  const customNavItems: NavItem[] = useMemo(() => {
    if (activeTab === 'payloads') {
      return allPayloads
        .filter(item => isCustomCategory(item.category))
        .map(item => ({
          id: `custom-payload-nav-${item.id}`,
          name: item.name,
          payloadId: item.id,
        }));
    }
    if (activeTab === 'tools') {
      return allToolCommands
        .filter(item => isCustomCategory(item.category))
        .map(item => ({
          id: `custom-tool-nav-${item.id}`,
          name: item.name,
          toolId: item.id,
        }));
    }
    return [];
  }, [activeTab, allPayloads, allToolCommands]);

  const data = useMemo(
    () => activeTab === 'payloads'
      ? allPayloadNavigation
      : activeTab === 'tools'
        ? allToolNavigation
        : activeTab === 'exploits'
          ? annotatedExploitNavigation
          : [],
    [activeTab, allPayloadNavigation, allToolNavigation, annotatedExploitNavigation],
  );

  // 选中处理（TreeNode 原 context 直读迁移而来）：叶子点击统一走这里。
  // useCallback 保证引用稳定，TreeNode 的 memo 比较器因此可通过。
  const handleSelect = useCallback((item: NavItem) => {
    if (item.payloadId) {
      setSelectedPayloadId(item.payloadId);
      setSelectedToolId(null);
      setSelectedExploitId(null);
      setSelectedExploitTypeId(null);
      onNavigate?.();
      return;
    }
    if (item.exploitId) {
      setSelectedExploitId(item.exploitId);
      setSelectedPayloadId(null);
      setSelectedToolId(null);
      setSelectedExploitTypeId(null);
      onNavigate?.();
      return;
    }
    if (item.toolId) {
      const tool = allToolCommands.find(candidate => candidate.id === item.toolId);
      if (tool?.externalUrl && openProtectedExternalLink(tool.externalUrl)) {
        onNavigate?.();
        return;
      }
      setSelectedToolId(item.toolId);
      setSelectedPayloadId(null);
      setSelectedExploitId(null);
      setSelectedExploitTypeId(null);
      onNavigate?.();
      return;
    }
    // EXP 分类树类型节点（标注 vulnType）：进入该漏洞类型的全量分类浏览
    if (item.vulnType) {
      setSelectedExploitTypeId(item.id);
      setSelectedPayloadId(null);
      setSelectedToolId(null);
      setSelectedExploitId(null);
      onNavigate?.();
    }
  }, [allToolCommands, onNavigate, setSelectedPayloadId, setSelectedToolId, setSelectedExploitId, setSelectedExploitTypeId]);

  const matchedIds = activeTab === 'payloads'
    ? searchMatches.payloadIds
    : activeTab === 'tools'
      ? searchMatches.toolIds
      : searchMatches.exploitIds;
  const matchCount = matchedIds.size;
  const isSearching = deferredSearchQuery.trim().length > 0;
  const firstVisibleRootId = useMemo(
    () => data.find(item => isTreeItemVisible(item, matchedIds, isSearching))?.id ?? null,
    [data, isSearching, matchedIds],
  );

  useEffect(() => {
    document.addEventListener('keydown', handleTreeKeyDown);
    return () => document.removeEventListener('keydown', handleTreeKeyDown);
  }, []);

  // E-18：切换内容域（payloads/tools/exploits）时树滚动回顶——新域的选中项常在中部，
  // 残留的滚动位置会让首屏从树中段开始。纯 DOM 滚动，无 setState。
  const treeContainerRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    treeContainerRef.current?.scrollTo(0, 0);
  }, [activeTab]);

  const sidebarTitle = activeTab === 'payloads'
    ? t('sidebar.attackCategories', language)
    : activeTab === 'tools'
      ? t('sidebar.toolCategories', language)
      : activeTab === 'exploits'
        ? (language === 'zh' ? 'EXP 漏洞分类' : 'Exploit Categories')
        : (language === 'zh' ? '自定义 Payload' : 'Custom Payload');

  return (
    <div className="sidebar-content">
      <div className="sidebar-header">
        <h2>{sidebarTitle}</h2>
        {activeTab === 'exploits' && selectedExploitTypeId && !isSearching && (
          <button
            type="button"
            className="tree-clear-type"
            onClick={() => setSelectedExploitTypeId(null)}
            title={language === 'zh' ? '回到全部分类浏览' : 'Back to browsing all categories'}
          >
            {language === 'zh' ? '× 清除分类' : '× Clear filter'}
          </button>
        )}
        {isSearching && (
          <span className="search-result-count" role="status" aria-live="polite">
            {t('sidebar.searchFound', language, { count: matchCount })}
          </span>
        )}
      </div>
      <div className="tree-container" ref={treeContainerRef} role="tree" aria-label={activeTab === 'payloads' ? 'Payload 分类' : activeTab === 'exploits' ? 'EXP 分类' : '工具分类'}>
        {isSearching && matchCount === 0 ? (
          <div className="no-search-results">
            <p>{t('sidebar.noResults', language)}</p>
            <span className="no-results-hint">{t('sidebar.noResultsHint', language)}</span>
          </div>
        ) : (
          <>
            {data.map(item => (
              <TreeNode
                key={item.id}
                item={item}
                level={0}
                matchedIds={matchedIds}
                forceExpand={isSearching}
                isSelected={(leafIdOf(item) !== '' && leafIdOf(item) === selectedLeafId) || item.id === selectedExploitTypeId}
                branchSelected={subtreeContains(item, selectedLeafId)}
                onSelect={handleSelect}
                isFirst={item.id === firstVisibleRootId}
                onNavigate={onNavigate}
                onCategoryPick={onCategoryPick}
                selectedLeafId={selectedLeafId}
                selectedExploitTypeId={selectedExploitTypeId}
              />
            ))}
            {(activeTab === 'payloads' || activeTab === 'tools') && customNavItems.length > 0 && !isSearching && (
              <CustomSection
                items={customNavItems}
                matchedIds={matchedIds}
                onNavigate={onNavigate}
                language={language}
                selectedLeafId={selectedLeafId}
                onSelect={handleSelect}
                isFirst={data.length === 0}
              />
            )}
          </>
        )}
      </div>
    </div>
  );
}
