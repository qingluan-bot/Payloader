import type { PayloadItem } from '../types';

// P1-2 首屏载荷瘦身：public-data 只含列表投影，详情级字段（WAF 变体/教程/攻击链/
// 执行命令全量语法解析）由本模块在打开详情时按需拉取并做会话级缓存。
// 内存 Map 是主缓存；sessionStorage 做跨刷新持久化，配额满或写失败静默放弃
//（内存缓存仍然有效），条目数封顶避免挤占其它 sessionStorage 键。

const DETAIL_KEY_PREFIX = 'payload-detail:';
const MAX_PERSISTED_ENTRIES = 40;

const memoryCache = new Map<string, PayloadItem>();
const persistOrder: string[] = [];
const inFlight = new Map<string, Promise<PayloadItem | null>>();

const readPersisted = (id: string): PayloadItem | null => {
  try {
    const raw = sessionStorage.getItem(DETAIL_KEY_PREFIX + id);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as PayloadItem;
    if (!parsed || typeof parsed.id !== 'string') return null;
    memoryCache.set(id, parsed);
    return parsed;
  } catch {
    return null;
  }
};

const persist = (item: PayloadItem) => {
  try {
    sessionStorage.setItem(DETAIL_KEY_PREFIX + item.id, JSON.stringify(item));
    persistOrder.push(item.id);
    while (persistOrder.length > MAX_PERSISTED_ENTRIES) {
      const oldest = persistOrder.shift();
      if (oldest && oldest !== item.id) sessionStorage.removeItem(DETAIL_KEY_PREFIX + oldest);
    }
  } catch { /* 配额满即放弃持久化 */ }
};

/** 同步读缓存（内存 → sessionStorage），未命中返回 null。 */
export const cachedPayloadDetail = (id: string): PayloadItem | null =>
  memoryCache.get(id) ?? readPersisted(id);

/**
 * 拉取 payload 完整条目：去重并发、失败返回 null（调用方回落列表态渲染）。
 */
export const fetchPayloadDetail = (id: string): Promise<PayloadItem | null> => {
  const pending = inFlight.get(id);
  if (pending) return pending;
  const request = (async () => {
    try {
      const response = await fetch(`/api/payloads/${encodeURIComponent(id)}/detail`);
      if (!response.ok) return null;
      const item = await response.json() as PayloadItem;
      if (!item || typeof item.id !== 'string') return null;
      memoryCache.set(id, item);
      persist(item);
      return item;
    } catch {
      return null;
    } finally {
      inFlight.delete(id);
    }
  })();
  inFlight.set(id, request);
  return request;
};
