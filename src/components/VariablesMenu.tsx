import type { RefObject } from 'react';
import { useLanguage } from '../appContext';
import { t } from '../i18n';
import { VariablesPanelBody } from './VariablesPanel';

interface VariablesMenuProps {
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
  variablesToggleRef: RefObject<HTMLButtonElement | null>;
  variablesPanelRef: RefObject<HTMLDivElement | null>;
}

// 头部变量下拉：只保留开关与面板头部（标题/关闭），编辑主体在 VariablesPanelBody（与移动端「更多」页共用）。
// B-7：抽屉加半透明遮罩（点击关闭；ESC/外点关闭由 Header 的 useDismissable 继续承担），遮罩
// 与抽屉都从顶栏下缘起（--app-header-height），不遮挡顶栏按钮；抽屉高度封顶防溢出视口。
function VariablesMenu({ open, onToggle, onClose, variablesToggleRef, variablesPanelRef }: VariablesMenuProps) {
  const { language } = useLanguage();

  return (
    <div className="variables-dropdown">
      <button
        ref={variablesToggleRef}
        type="button"
        className="variables-toggle"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls="variables-panel"
      >
        {t('header.variables', language)}
      </button>
      {open && (
        <div
          className="variables-overlay"
          onClick={onClose}
          aria-hidden="true"
          style={{
            position: 'fixed',
            top: 'var(--app-header-height)',
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.45)',
            zIndex: 999,
          }}
        />
      )}
      {open && (
        <div
          ref={variablesPanelRef}
          className="variables-panel"
          id="variables-panel"
          style={{ maxHeight: 'calc(100dvh - var(--app-header-height) - 16px)', overflowY: 'auto' }}
        >
          <div className="variables-header">
            <div>
              <h3>{t('header.variablesTitle', language)}</h3>
              <span className="variables-hint">{t('header.variablesHint', language)}</span>
            </div>
            <button type="button" className="variables-close" onClick={onClose} aria-label="关闭全局变量">×</button>
          </div>
          <VariablesPanelBody />
        </div>
      )}
    </div>
  );
}

export default VariablesMenu;
