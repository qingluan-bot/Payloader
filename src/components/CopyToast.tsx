import { useEffect, useState } from 'react';
import { COPIED_EVENT } from '../utils/clipboard';

// 移动端复制成功 toast（M3）：监听全局复制事件，短反馈后自动消失。
// 桌面按钮自带「已复制」文案反馈，本组件仅移动端挂载（App 门控）。
function CopyToast() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    let timer: number | null = null;
    const show = () => {
      setVisible(true);
      if (timer !== null) window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        timer = null;
        setVisible(false);
      }, 1600);
    };
    window.addEventListener(COPIED_EVENT, show);
    return () => {
      window.removeEventListener(COPIED_EVENT, show);
      if (timer !== null) window.clearTimeout(timer);
    };
  }, []);

  if (!visible) return null;
  return (
    <div className="copy-toast" role="status" aria-live="polite">
      已复制到剪贴板
    </div>
  );
}

export default CopyToast;
