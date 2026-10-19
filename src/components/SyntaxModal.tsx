import type { SyntaxPart, I18nText } from '../types';
import { useEffect, useId, useRef } from 'react';
import { useLanguage, useSession } from '../appContext';
import { t, getText } from '../i18n';
import { resolveVariableText } from '../utils/variables';
import '../styles/syntax-modal.css';

interface SyntaxModalProps {
  syntax: SyntaxPart[];
  title: I18nText;
  onClose: () => void;
}

function SyntaxModal({ syntax, title, onClose }: SyntaxModalProps) {
  const { globalVariables } = useSession();
  const { language } = useLanguage();
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);
  const titleId = useId();

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    const focusableSelector = 'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])';
    const focusDialog = window.requestAnimationFrame(() => {
      (dialog?.querySelector<HTMLElement>(focusableSelector) || dialog)?.focus();
    });

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== 'Tab' || !dialog) return;

      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(focusableSelector))
        .filter(element => element.offsetParent !== null);
      if (!focusable.length) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => {
      window.cancelAnimationFrame(focusDialog);
      document.removeEventListener('keydown', handleKeyDown);
      previousFocus.current?.focus();
    };
  }, []);

  // 19种SyntaxPart type的完整颜色映射 (name now from i18n)
  // 全部走 token（--code-*/--sev-*/--state-*/--src-*/--accent 族）：19 类映射到
  // 12 个 token 色相，个别类共享近色（图例有文字标注区分）。
  const typeColorMap: Record<string, { color: string; group: string }> = {
    // 基础语法类
    command:    { color: 'var(--accent)',          group: 'basic' },
    parameter:  { color: 'var(--neon-orange)',     group: 'basic' },
    value:      { color: 'var(--state-success)',   group: 'basic' },
    operator:   { color: 'var(--neon-pink)',       group: 'basic' },
    variable:   { color: 'var(--sev-medium)',      group: 'basic' },
    // Web安全类
    header:     { color: 'var(--code-meta)',       group: 'web' },
    method:     { color: 'var(--code-keyword)',    group: 'web' },
    domain:     { color: 'var(--src-metasploit)',  group: 'web' },
    path:       { color: 'var(--state-success)',   group: 'web' },
    tag:        { color: 'var(--src-nuclei)',      group: 'web' },
    json:       { color: 'var(--sev-low)',         group: 'web' },
    // 编码与技术类
    encoding:   { color: 'var(--sev-medium)',      group: 'tech' },
    technique:  { color: 'var(--code-function)',   group: 'tech' },
    format:     { color: 'var(--neon-pink)',       group: 'tech' },
    function:   { color: 'var(--code-string)',     group: 'tech' },
    keyword:    { color: 'var(--sev-high)',        group: 'tech' },
    concept:    { color: 'var(--code-function)',   group: 'tech' },
    char:       { color: 'var(--state-success)',   group: 'tech' },
    'tool-mode':{ color: 'var(--neon-orange)',     group: 'tech' },
  };

  const getTypeColor = (type: string) => {
    return typeColorMap[type]?.color || 'var(--text-secondary)';
  };

  const getTypeName = (type: string) => {
    const key = `syntax.${type}` as Parameters<typeof t>[0];
    const result = t(key, language);
    // If key not found, t() returns the key itself - fall back to 'Other'
    return result === key ? t('syntax.other', language) : result;
  };

  // 从当前语法数据中收集使用到的type，用于动态图例
  const usedTypes = [...new Set(syntax.map(s => s.type).filter(Boolean))] as string[];

  return (
    <div className="modal-overlay" onMouseDown={event => {
      if (event.target === event.currentTarget) onClose();
    }}>
      <div
        ref={dialogRef}
        className="modal-content"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className="modal-header">
          <h3 id={titleId}>{t('syntax.title', language)}{getText(title, language)}</h3>
          <button type="button" className="modal-close" onClick={onClose} aria-label="关闭语法解析">×</button>
        </div>
        <div className="modal-body">
          <div className="syntax-legend">
            {usedTypes.map(tp => (
              <span key={tp} className="legend-item">
                <span className="dot" style={{ background: getTypeColor(tp) }}></span>
                {getTypeName(tp)}
              </span>
            ))}
          </div>
          <div className="syntax-list">
            {syntax.map((item, index) => (
              <div key={index} className="syntax-item">
                <div className="syntax-part-wrapper">
                  <code 
                    className="syntax-part"
                    style={{ 
                      borderColor: getTypeColor(item.type || ''),
                      color: getTypeColor(item.type || '')
                    }}
                  >
                    {resolveVariableText(item.part, globalVariables)}
                  </code>
                  {item.type && (
                    <span 
                      className="syntax-type"
                      style={{ backgroundColor: getTypeColor(item.type) }}
                    >
                      {getTypeName(item.type)}
                    </span>
                  )}
                </div>
                <div className="syntax-explanation">
                  {resolveVariableText(getText(item.explanation, language), globalVariables)}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default SyntaxModal;
