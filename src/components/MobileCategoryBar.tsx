import { useCallback, useMemo, useState } from 'react';
import { useLanguage, useNav, useStaticData } from '../appContext';
import { getText } from '../i18n';
import { exploitTreeTypeMap } from '../utils/exploit-tree';
import { findNavNodeById } from '../utils/navigationTree';
import type { NavItem } from '../types';
import { BottomSheet } from './BottomSheet';
import { NavTree } from './NavTree';

// 移动端「当前分类」横条（M1）：分类树在移动端不常驻，列表页顶部以此条承载分类上下文，
// 点击弹 BottomSheet 内嵌 NavTree 选分类。仅列表视图渲染（详情全屏接管时由 MainContent 门控）。
function MobileCategoryBar() {
  const {
    activeTab,
    selectedPayloadId,
    selectedToolId,
    selectedExploitTypeId,
    mobileCategoryId,
    setMobileCategoryId,
  } = useNav();
  const { allPayloads, allToolCommands, allPayloadNavigation, allToolNavigation } = useStaticData();
  const { language } = useLanguage();
  const [sheetOpen, setSheetOpen] = useState(false);
  const closeSheet = useCallback(() => setSheetOpen(false), []);

  const handleCategoryPick = useCallback((item: NavItem) => {
    setMobileCategoryId(item.id);
    closeSheet();
  }, [setMobileCategoryId, closeSheet]);

  const categoryLabel = useMemo(() => {
    if (mobileCategoryId && (activeTab === 'payloads' || activeTab === 'tools')) {
      const nav = activeTab === 'payloads' ? allPayloadNavigation : allToolNavigation;
      const node = findNavNodeById(nav, mobileCategoryId);
      if (node) return getText(node.name, language);
    }
    if (activeTab === 'payloads' && selectedPayloadId) {
      const payload = allPayloads.find(item => item.id === selectedPayloadId);
      if (payload) return getText(payload.category, language);
    }
    if (activeTab === 'tools' && selectedToolId) {
      const tool = allToolCommands.find(item => item.id === selectedToolId);
      if (tool) return getText(tool.category, language);
    }
    if (activeTab === 'exploits' && selectedExploitTypeId) {
      const mapping = exploitTreeTypeMap[selectedExploitTypeId];
      if (mapping) return mapping.label;
    }
    return activeTab === 'exploits'
      ? (language === 'zh' ? '全部条目' : 'All entries')
      : (language === 'zh' ? '全部分类' : 'All categories');
  }, [mobileCategoryId, activeTab, selectedPayloadId, selectedToolId, selectedExploitTypeId, allPayloads, allToolCommands, allPayloadNavigation, allToolNavigation, language]);

  return (
    <>
      <button
        type="button"
        className="mobile-category-bar"
        aria-haspopup="dialog"
        aria-expanded={sheetOpen}
        onClick={() => setSheetOpen(true)}
      >
        <span className="mobile-category-current">
          <span className="mobile-category-caption">{language === 'zh' ? '分类' : 'Category'}</span>
          <span className="mobile-category-label">{categoryLabel}</span>
        </span>
        <span className="mobile-category-chevron" aria-hidden="true">▾</span>
      </button>
      <BottomSheet open={sheetOpen} onClose={closeSheet} title={language === 'zh' ? '选择分类' : 'Choose a category'}>
        <div className="mobile-category-sheet-tree">
          <NavTree onNavigate={closeSheet} onCategoryPick={handleCategoryPick} />
        </div>
      </BottomSheet>
    </>
  );
}

export default MobileCategoryBar;
