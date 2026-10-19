import type { JSX } from 'react';
import { getText } from '../i18n';
import type { I18nText, PayloadExecution, SyntaxPart } from '../types';
import { label } from './payloadDetailText';

interface ExecutionItemProps {
  exec: PayloadExecution;
  index: number;
  language: 'zh' | 'en';
  copiedKey: string | null;
  onCopy: (text: string, index: string) => void;
  onSelectSyntax: (next: { syntax: SyntaxPart[]; title: I18nText }) => void;
  renderCommand: (command: string) => JSX.Element;
}

function ExecutionItem({ exec, index, language, copiedKey, onCopy, onSelectSyntax, renderCommand }: ExecutionItemProps) {
  const platformLabel = (platform?: PayloadExecution['platform']) => {
    if (platform === 'windows') return label('platformWindows', language);
    if (platform === 'linux') return label('platformLinux', language);
    return label('platformAll', language);
  };

  const copyId = `item-${index}`;

  return (
    <article key={`${getText(exec.title, language)}-${index}-${exec.command}`} className="execution-item">
      <div className="execution-content">
        <div className="execution-header">
          <div className="execution-heading">
            <span className="item-index">{String(index + 1).padStart(2, '0')}</span>
            <h4 className="execution-title">{getText(exec.title, language)}</h4>
          </div>
          {exec.requiresAdmin && (
            <div className="execution-badges">
              <span className="badge admin">{label('admin', language)}</span>
            </div>
          )}
        </div>
        {exec.description && <p className="execution-desc">{getText(exec.description, language)}</p>}
        <div className="code-block-wrapper">
          {/* E-13：语法解析按钮移入代码块头部，与「复制」并排（原区块分隔线间的 code-actions 退役） */}
          <div className="code-block">
            <div className="code-block-head">
              <span className="code-lang">{platformLabel(exec.platform)}</span>
              {exec.syntaxBreakdown?.length ? (
                <button
                  type="button"
                  className="syntax-btn"
                  onClick={() => onSelectSyntax({ syntax: exec.syntaxBreakdown!, title: exec.title })}
                >
                  {label('syntax', language)}
                </button>
              ) : null}
              <button
                type="button"
                className={`copy-btn ${copiedKey === copyId ? 'copied' : ''}`}
                onClick={() => onCopy(exec.command, copyId)}
              >
                {copiedKey === copyId ? label('copied', language) : label('copy', language)}
              </button>
            </div>
            <pre className="code-block-pre">{renderCommand(exec.command)}</pre>
          </div>
        </div>
      </div>
    </article>
  );
}

export default ExecutionItem;
