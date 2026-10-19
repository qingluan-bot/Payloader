import { useEffect } from 'react';
import { useNav } from '../appContext';
import { NavTree } from './NavTree';
import '../styles/sidebar.css';

interface SidebarProps {
  collapsed: boolean;
  onClose?: () => void;
  onNavigate?: () => void;
}

// 桌面侧栏抽屉壳：只负责 aside 语义、折叠态（inert/aria-hidden）与窄屏抽屉的 ESC 关闭。
// 分类树本体在 NavTree（与移动端分类选择 sheet 共用）。移动端（≤768px）本组件不挂载（App 门控），
// 分类浏览走列表页顶部的 MobileCategoryBar。底部小字图例（E-16）解释树内 P/T 徽标含义。
function Sidebar({ collapsed, onClose, onNavigate }: SidebarProps) {
  const { activeTab } = useNav();

  useEffect(() => {
    if (collapsed) return;

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && window.matchMedia('(max-width: 900px)').matches) {
        onClose?.();
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [collapsed, onClose]);

  return (
    <aside
      id="primary-navigation"
      className={`sidebar ${collapsed ? 'collapsed' : ''}`}
      aria-label={activeTab === 'payloads' ? 'Payload 分类导航' : activeTab === 'exploits' ? 'EXP 分类导航' : '工具分类导航'}
      aria-hidden={collapsed}
      inert={collapsed}
    >
      <NavTree onNavigate={onNavigate} />
      <p className="sidebar-legend" aria-hidden="true">
        {activeTab === 'payloads'
          ? 'P=载荷条目'
          : activeTab === 'tools'
            ? 'T=工具条目'
            : 'E=EXP 条目'}
      </p>
    </aside>
  );
}

export default Sidebar;
