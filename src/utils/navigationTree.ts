import type { NavItem } from '../types';

// 导航树工具（MobileCategoryBar / MobileCategoryList 共用）：mobileCategoryId 只存节点 id，
// 树引用随 publicData 重建，按 id 查找；分类列表需要收集分类子树的叶子。

export function findNavNodeById(items: NavItem[], id: string): NavItem | null {
  for (const item of items) {
    if (item.id === id) return item;
    const child = item.children ? findNavNodeById(item.children, id) : null;
    if (child) return child;
  }
  return null;
}

// 收集分类子树的内容叶子（虚拟分组节点无 payloadId/toolId，递归穿透）
export function collectNavLeaves(item: NavItem): NavItem[] {
  if (!item.children?.length) {
    return item.payloadId || item.toolId ? [item] : [];
  }
  return item.children.flatMap(collectNavLeaves);
}
