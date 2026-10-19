import { useLanguage, useNav } from '../appContext';
import type { ActiveTab } from '../appContext';
import { Icon } from './Icon';
import type { IconName } from './Icon';

// 移动端底部固定导航（M1 主导航唯一形态）：Payload / 工具 / EXP / 更多。
// 顶部 tab-switcher 与汉堡按钮在移动端退役；CTF 开启时入口收进「更多」页（不占四项）。
function MobileNav() {
  const {
    activeTab,
    setActiveTab,
    activeView,
    setActiveView,
    setSelectedPayloadId,
    setSelectedToolId,
    setSelectedExploitId,
    setMobileCategoryId,
  } = useNav();
  const { language } = useLanguage();

  const switchTab = (tab: ActiveTab) => {
    setActiveView('workspace');
    setActiveTab(tab);
    setSelectedPayloadId(null);
    setSelectedToolId(null);
    setSelectedExploitId(null);
    setMobileCategoryId(null);
  };

  const moreActive = activeView === 'more' || activeTab === 'ctf';

  const items: { tab: ActiveTab | 'more'; icon: IconName; label: string }[] = [
    { tab: 'payloads', icon: 'zap', label: 'Payload' },
    { tab: 'tools', icon: 'settings', label: language === 'zh' ? '工具' : 'Tools' },
    { tab: 'exploits', icon: 'bug', label: 'EXP' },
    { tab: 'more', icon: 'more-horizontal', label: language === 'zh' ? '更多' : 'More' },
  ];

  return (
    <nav className="mobile-nav" aria-label="主导航">
      {items.map(item => {
        const active = item.tab === 'more'
          ? moreActive
          : activeView !== 'more' && activeTab === item.tab;
        return (
          <button
            key={item.tab}
            type="button"
            className={`mobile-nav-item ${active ? 'active' : ''}`}
            aria-current={active ? 'page' : undefined}
            onClick={() => {
              if (item.tab === 'more') {
                setActiveView('more');
                return;
              }
              switchTab(item.tab);
            }}
          >
            <span className="mobile-nav-icon" aria-hidden="true"><Icon name={item.icon} size={20} /></span>
            <span className="mobile-nav-label">{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
}

export default MobileNav;
