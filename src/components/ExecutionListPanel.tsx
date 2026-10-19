import type { ChangeEvent, JSX } from 'react';
import { useLanguage, useNav } from '../appContext';
import { getText } from '../i18n';
import type { I18nText, PayloadExecution, SyntaxPart } from '../types';
import { countLabel, label } from './payloadDetailText';
import ListState from './ListState';
import ExecutionItem from './ExecutionItem';

interface ExecutionListPanelProps {
  items: PayloadExecution[];
  totalCount: number;
  modeLabel: string;
  hasWafContent: boolean;
  payloadQuery: string;
  onQueryChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onClearQuery: () => void;
  copiedKey: string | null;
  onCopy: (text: string, index: string) => void;
  onCopyVisible: () => void;
  onSelectSyntax: (next: { syntax: SyntaxPart[]; title: I18nText }) => void;
  renderCommand: (command: string) => JSX.Element;
}

function ExecutionListPanel({
  items,
  totalCount,
  modeLabel,
  hasWafContent,
  payloadQuery,
  onQueryChange,
  onClearQuery,
  copiedKey,
  onCopy,
  onCopyVisible,
  onSelectSyntax,
  renderCommand,
}: ExecutionListPanelProps) {
  const { bypassMode, setBypassMode } = useNav();
  const { language } = useLanguage();
  // E-09：筛选把结果清零时绿 chip 置灰（"WAF 内容可用"描述的是全部内容，此刻语义不成立）
  const filterEmpty = !items.length && payloadQuery.trim().length > 0;

  return (
    <div className="execution-section" role="tabpanel">
      <div className="execution-toolbar">
        <div className="payload-list-info">
          <span className="mode-label">{modeLabel}</span>
          <span className="item-count">{countLabel(items.length, totalCount, language)}</span>
          <span
            className={`waf-content-status ${hasWafContent ? 'available' : 'unavailable'}${filterEmpty ? ' filtered' : ''}`}
            title={filterEmpty
              ? (language === 'zh' ? '当前筛选没有命中，WAF 内容可用性以全部内容为准' : 'No filter hits; WAF availability refers to the full content')
              : undefined}
          >
            {hasWafContent ? label('wafAvailable', language) : label('wafUnavailable', language)}
          </span>
        </div>
        <button
          className={`copy-all-btn ${copiedKey === 'all' ? 'copied' : ''}`}
          onClick={onCopyVisible}
          disabled={!items.length}
        >
          {copiedKey === 'all' ? label('copiedVisible', language) : label('copyVisible', language)}
        </button>
      </div>

      <div className="payload-controls">
        <div className="payload-search-field">
          <input
            type="search"
            name="payload-command-search"
            value={payloadQuery}
            onChange={onQueryChange}
            placeholder={label('searchPlaceholder', language)}
            aria-label={label('searchPlaceholder', language)}
          />
          {payloadQuery && (
            <button type="button" onClick={onClearQuery} aria-label={label('clearSearch', language)}>
              ×
            </button>
          )}
        </div>
      </div>

      {!items.length ? (
        // B-9：空态对齐 EXP 域三态组件（图标 + 标题 + 说明 + 行动按钮）
        bypassMode === 'waf' && !hasWafContent ? (
          <ListState
            variant="empty"
            title={label('noWafTitle', language)}
            description={label('noWafHint', language)}
            actionLabel={label('backToNormal', language)}
            onAction={() => setBypassMode('normal')}
          />
        ) : (
          <ListState
            variant="empty"
            title={label('noItemsTitle', language)}
            description={label('noItemsHint', language)}
            actionLabel={label('clearFilters', language)}
            onAction={onClearQuery}
          />
        )
      ) : (
        <div className="execution-list">
          {items.map((exec, index) => (
            <ExecutionItem
              key={`${getText(exec.title, language)}-${index}-${exec.command}`}
              exec={exec}
              index={index}
              language={language}
              copiedKey={copiedKey}
              onCopy={onCopy}
              onSelectSyntax={onSelectSyntax}
              renderCommand={renderCommand}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default ExecutionListPanel;
