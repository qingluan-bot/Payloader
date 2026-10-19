import { useMemo } from 'react';
import { useLanguage, useNav, useStaticData } from '../appContext';
import { getText } from '../i18n';
import { collectNavLeaves, findNavNodeById } from '../utils/navigationTree';
import ListState from './ListState';

interface MobileCategoryListProps {
  categoryId: string;
  onOpenPayload: (payloadId: string) => void;
  onOpenTool: (toolId: string) => void;
}

// 移动端分类条目列表（M2）：payload/工具域选中分类后渲染该分类子树叶子的单列列表，
// 点条目进详情。桌面无此视图（桌面用侧栏树驱动）。
function MobileCategoryList({ categoryId, onOpenPayload, onOpenTool }: MobileCategoryListProps) {
  const { activeTab } = useNav();
  const { allPayloadNavigation, allToolNavigation, allPayloads, allToolCommands } = useStaticData();
  const { language } = useLanguage();

  const entries = useMemo(() => {
    const nav = activeTab === 'tools' ? allToolNavigation : allPayloadNavigation;
    const node = findNavNodeById(nav, categoryId);
    if (!node) return [];
    return collectNavLeaves(node).map(leaf => {
      if (leaf.payloadId) {
        const payload = allPayloads.find(item => item.id === leaf.payloadId);
        if (!payload) return null;
        return {
          key: leaf.id,
          title: getText(payload.name, language),
          description: getText(payload.description, language),
          open: () => onOpenPayload(payload.id),
        };
      }
      if (leaf.toolId) {
        const tool = allToolCommands.find(item => item.id === leaf.toolId);
        if (!tool) return null;
        return {
          key: leaf.id,
          title: getText(tool.name, language),
          description: getText(tool.description, language),
          open: () => onOpenTool(tool.id),
        };
      }
      return null;
    }).filter(Boolean) as { key: string; title: string; description: string; open: () => void }[];
  }, [activeTab, categoryId, allPayloadNavigation, allToolNavigation, allPayloads, allToolCommands, language, onOpenPayload, onOpenTool]);

  if (!entries.length) {
    return (
      <ListState
        variant="empty"
        title={language === 'zh' ? '该分类暂无条目' : 'No entries in this category'}
        description={language === 'zh' ? '换个分类看看，或用顶部搜索直接找内容。' : 'Try another category, or search from the top bar.'}
      />
    );
  }

  return (
    <div className="mobile-category-list" aria-label={language === 'zh' ? '分类条目列表' : 'Category entries'}>
      {entries.map(entry => (
        <button key={entry.key} type="button" className="mobile-category-item" onClick={entry.open}>
          <span className="mobile-category-item-title">{entry.title}</span>
          {entry.description && (
            <span className="mobile-category-item-desc">{entry.description}</span>
          )}
        </button>
      ))}
    </div>
  );
}

export default MobileCategoryList;
