import { useEffect, useRef } from 'react';
import type { ReactNode, RefObject } from 'react';
import { createPortal } from 'react-dom';
import { useFocusTrap } from './useFocusTrap';

interface BottomSheetProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
}

// 移动端底部抽屉：portal 渲染 + 焦点陷阱（useFocusTrap：锁滚动/聚焦/Tab 圈定/ESC）。
// 系统返回键：打开时 pushState 占位，Android 返回/iOS 侧滑触发 popstate → onClose；
// ESC/backdrop 等程序化关闭时在 cleanup 里 history.back() 撤销占位，栈不残留。
// onClose 经 ref 解耦，父组件传内联箭头也不会导致本 effect 重跑压栈。
export function BottomSheet({ open, onClose, title, children }: BottomSheetProps) {
  const sheetRef = useRef<HTMLDivElement>(null);
  const closeBtnRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  const popstateClosingRef = useRef(false);

  useEffect(() => {
    onCloseRef.current = onClose;
  });

  useFocusTrap({
    enabled: open,
    dialogRef: sheetRef,
    fallbackFocusRef: closeBtnRef as RefObject<HTMLElement | null>,
    onClose: () => onCloseRef.current(),
  });

  useEffect(() => {
    if (!open) return;
    popstateClosingRef.current = false;
    // 占位条目：pushState 不改 URL，仅标记「返回键一次 = 关闭 sheet」
    history.pushState({ payloaderSheet: true }, '');
    const handlePopstate = () => {
      popstateClosingRef.current = true;
      onCloseRef.current();
    };
    window.addEventListener('popstate', handlePopstate);
    return () => {
      window.removeEventListener('popstate', handlePopstate);
      if (!popstateClosingRef.current) {
        // 程序化关闭：当前条目仍是占位条目（push 后未导航），只清占位 state 即可。
        // 不能 history.back()——它的异步导航会与深链 hash 同步（syncHashForState 的
        // replaceState）竞争，回到旧条目触发 hashchange 重放，把用户刚做的选中清掉。
        // state 守卫：未来若两 sheet 叠开，先关者的 cleanup 不得清掉后开者的占位标记。
        if (history.state?.payloaderSheet) {
          history.replaceState(null, '');
        }
      }
    };
  }, [open]);

  if (!open) return null;

  return createPortal(
    <div
      className="bottom-sheet-overlay"
      onMouseDown={event => {
        if (event.target === event.currentTarget) onCloseRef.current();
      }}
    >
      <div
        ref={sheetRef}
        className="bottom-sheet"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
      >
        <div className="bottom-sheet-grabber" aria-hidden="true" />
        <header className="bottom-sheet-head">
          <h2>{title}</h2>
          <button
            ref={closeBtnRef}
            type="button"
            className="bottom-sheet-close"
            onClick={() => onCloseRef.current()}
            aria-label="关闭"
          >
            ×
          </button>
        </header>
        <div className="bottom-sheet-body">{children}</div>
      </div>
    </div>,
    document.body,
  );
}
