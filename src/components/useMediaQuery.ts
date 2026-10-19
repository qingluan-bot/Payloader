import { useEffect, useState } from 'react';

// 移动断点唯一权威：CSS 侧 mobile.css 的 @media (max-width: 768px) 与此对齐，改一处必须同步另一处。
export const MOBILE_BREAKPOINT = '(max-width: 768px)';

// 布尔媒体查询订阅。初始值取自 lazy initializer（query 为模块常量，初始化后不变）；
// effect 内仅在 change 事件回调里 setState——同步路径 setState 会触发 react-hooks/set-state-in-effect。
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches);

  useEffect(() => {
    const media = window.matchMedia(query);
    const apply = (event: MediaQueryListEvent) => setMatches(event.matches);
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, [query]);

  return matches;
}
