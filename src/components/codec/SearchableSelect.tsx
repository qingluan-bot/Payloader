import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { useLanguage } from '../../appContext';
import { useDismissable } from '../useDismissable';
import { Icon } from '../Icon';

export interface SearchableSelectGroup {
  key: string;
  // null = 无分组标题（选项直接平铺）
  label: string | null;
  options: Array<{ value: string; text: string }>;
}

interface SearchableSelectProps {
  value: string;
  groups: SearchableSelectGroup[];
  onChange: (value: string) => void;
  // 字段名（「算法 / 场景」），用于 listbox aria-label 与触发按钮 aria-label
  fieldLabel: string;
}

// 可搜索下拉（F-08）：原生 select 换 combobox——顶部固定过滤输入框 + 分组选项面板。
// 可访问性：触发按钮 aria-haspopup/aria-expanded；输入框 role=combobox + aria-controls/aria-activedescendant；
// 选项 role=option + aria-selected；键盘 ↑↓ 移动、Enter 选中、Esc 关闭归还焦点、Home/End 跳边界。
export function SearchableSelect({ value, groups, onChange, fieldLabel }: SearchableSelectProps) {
  const { language } = useLanguage();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const listboxId = useId();

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return groups;
    return groups
      .map(group => ({
        ...group,
        options: group.options.filter(option =>
          option.text.toLowerCase().includes(needle) || option.value.toLowerCase().includes(needle)),
      }))
      .filter(group => group.options.length > 0);
  }, [groups, query]);

  const flatOptions = useMemo(() => visible.flatMap(group => group.options), [visible]);
  const selectedText = useMemo(
    () => flatOptions.find(option => option.value === value)?.text
      ?? groups.flatMap(group => group.options).find(option => option.value === value)?.text
      ?? value,
    [flatOptions, groups, value],
  );

  const close = (refocus: boolean) => {
    setOpen(false);
    setQuery('');
    if (refocus) triggerRef.current?.focus();
  };

  useDismissable({
    enabled: open,
    containerRef: panelRef,
    buttonRef: triggerRef,
    onClose: () => close(false),
    getEscapeFocusTarget: () => triggerRef.current,
  });

  const openPanel = () => {
    const selectedIndex = groups.flatMap(group => group.options).findIndex(option => option.value === value);
    setQuery('');
    setActiveIndex(Math.max(0, selectedIndex));
    setOpen(true);
  };

  const select = (optionValue: string) => {
    onChange(optionValue);
    close(true);
  };

  const step = (delta: number) => {
    if (!flatOptions.length) return;
    setActiveIndex(index => (index + delta + flatOptions.length) % flatOptions.length);
  };

  const handleInputKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        step(1);
        break;
      case 'ArrowUp':
        event.preventDefault();
        step(-1);
        break;
      case 'Home':
        event.preventDefault();
        setActiveIndex(0);
        break;
      case 'End':
        event.preventDefault();
        setActiveIndex(Math.max(0, flatOptions.length - 1));
        break;
      case 'Enter':
        event.preventDefault();
        if (flatOptions[activeIndex]) select(flatOptions[activeIndex].value);
        break;
      case 'Tab':
        setOpen(false);
        setQuery('');
        break;
      default:
        break;
    }
  };

  // 活动选项滚入视野：DOM 副作用（非 setState），block:nearest 避免整面板跳动
  const activeOptionValue = flatOptions[activeIndex]?.value;
  useEffect(() => {
    if (!open || !activeOptionValue) return;
    listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [open, activeOptionValue]);

  return (
    <div className="codec-combo">
      <button
        type="button"
        ref={triggerRef}
        className="codec-combo-trigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={`${fieldLabel}: ${selectedText}`}
        onClick={() => (open ? close(false) : openPanel())}
      >
        <span>{selectedText}</span>
        <Icon name="chevron-down" size={14} />
      </button>
      {open && (
        <div className="codec-combo-panel" ref={panelRef}>
          <input
            className="codec-combo-filter"
            type="text"
            role="combobox"
            autoFocus
            spellCheck={false}
            value={query}
            aria-expanded
            aria-controls={listboxId}
            aria-activedescendant={activeOptionValue ? `${listboxId}-${activeOptionValue}` : undefined}
            aria-label={language === 'zh' ? `搜索${fieldLabel}` : `Search ${fieldLabel}`}
            placeholder={language === 'zh' ? '输入关键词过滤…' : 'Type to filter…'}
            onChange={event => {
              setQuery(event.target.value);
              setActiveIndex(0);
            }}
            onKeyDown={handleInputKeyDown}
          />
          <div className="codec-combo-list" role="listbox" id={listboxId} aria-label={fieldLabel} ref={listRef}>
            {visible.map(group => (
              <div key={group.key} className="codec-combo-group" role="presentation">
                {group.label && <div className="codec-combo-group-title">{group.label}</div>}
                {group.options.map(option => {
                  const flatIndex = flatOptions.indexOf(option);
                  const selected = option.value === value;
                  const active = flatIndex === activeIndex;
                  return (
                    <div
                      key={option.value}
                      id={`${listboxId}-${option.value}`}
                      role="option"
                      aria-selected={selected}
                      data-active={active ? 'true' : undefined}
                      className="codec-combo-option"
                      onClick={() => select(option.value)}
                      onMouseEnter={() => setActiveIndex(flatIndex)}
                    >
                      {option.text}
                    </div>
                  );
                })}
              </div>
            ))}
            {!flatOptions.length && (
              <div className="codec-combo-empty" role="presentation">
                {language === 'zh' ? '无匹配项' : 'No matches'}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
