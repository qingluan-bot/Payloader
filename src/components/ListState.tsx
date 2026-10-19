import type { ReactNode } from 'react';
import { stripLeadingPictographs } from '../utils/stripPictographs';
import { Icon } from './Icon';

// 列表三态（加载/空/错误）统一组件：三库列表与后台共用同一套样式类（global.css .state-*）。
// loading=骨架屏卡片呼吸占位；empty=图标+一句话+行动按钮；error=红边卡片+重试按钮。

// 工作台式空态（D-6/A7）：三域首页共用（payload/exp/tools）。左对齐小标题 + 一行说明 +
// 主按钮（进入第一分类）+ 常用分类降级为紧凑 chip 行内链接，替代原居中营销页式空态。
// 样式见 main-content.css .workbench-empty。

export interface WorkbenchEmptyAction {
  label: string;
  onSelect: () => void;
}

interface WorkbenchEmptyProps {
  title: string;
  description: string;
  /** 主按钮文案（如"从「Web应用攻防」开始"）；不传则不渲染主按钮 */
  primaryLabel?: string;
  onPrimary?: () => void;
  /** 常用分类 chip 列表（紧凑行内链接，不再是大卡片堆） */
  actions?: WorkbenchEmptyAction[];
  /** chip 容器 aria-label（如"常用分类"） */
  actionsLabel?: string;
}

interface ListStateProps {
  variant: 'loading' | 'empty' | 'error';
  /** 空/错误态标题（一句话说明发生了什么） */
  title?: string;
  /** 补充说明（为什么 + 能做什么） */
  description?: string;
  /** 行动按钮文案（空态如"清除筛选"、错误态如"重试"） */
  actionLabel?: string;
  onAction?: () => void;
  /** loading 骨架卡片数量 */
  skeletonRows?: number;
  className?: string;
  children?: ReactNode;
}

const SearchIcon = () => (
  <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
    <circle cx="11" cy="11" r="7" />
    <path d="m20 20-3.8-3.8" />
  </svg>
);

const AlertIcon = () => (
  <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
    <path d="M12 3.5 21.5 20h-19L12 3.5Z" strokeLinejoin="round" />
    <path d="M12 10v4.5" />
    <path d="M12 17.4v.2" />
  </svg>
);

function ListState({ variant, title, description, actionLabel, onAction, skeletonRows = 6, className = '', children }: ListStateProps) {
  if (variant === 'loading') {
    return (
      <div className={`state-block state-skeleton ${className}`} role="status" aria-live="polite" aria-label={title || 'Loading'}>
        {Array.from({ length: skeletonRows }, (_, index) => (
          <div key={index} className="state-skeleton-card" aria-hidden="true">
            <span className="skeleton-line skeleton-title" />
            <span className="skeleton-line" />
            <span className="skeleton-line skeleton-short" />
          </div>
        ))}
      </div>
    );
  }

  if (variant === 'error') {
    return (
      <div className={`state-block state-error ${className}`} role="alert">
        <AlertIcon />
        <strong>{title}</strong>
        {description && <span>{description}</span>}
        {actionLabel && onAction && (
          <button type="button" className="state-action" onClick={onAction}>{actionLabel}</button>
        )}
        {children}
      </div>
    );
  }

  return (
    <div className={`state-block state-empty ${className}`}>
      <SearchIcon />
      <strong>{title}</strong>
      {description && <span>{description}</span>}
      {actionLabel && onAction && (
        <button type="button" className="state-action" onClick={onAction}>{actionLabel}</button>
      )}
      {children}
    </div>
  );
}

export function WorkbenchEmpty({ title, description, primaryLabel, onPrimary, actions = [], actionsLabel }: WorkbenchEmptyProps) {
  return (
    <section className="workbench-empty">
      <h2>{title}</h2>
      <p>{description}</p>
      {primaryLabel && onPrimary && (
        <button type="button" className="workbench-empty-primary" onClick={onPrimary}>
          <span>{stripLeadingPictographs(primaryLabel)}</span>
          <Icon name="arrow-right" size={14} />
        </button>
      )}
      {actions.length > 0 && (
        <div className="workbench-empty-chips" aria-label={actionsLabel}>
          {actions.map(action => {
            const label = stripLeadingPictographs(action.label);
            return <button key={action.label} type="button" onClick={action.onSelect}>{label}</button>;
          })}
        </div>
      )}
    </section>
  );
}

export default ListState;
