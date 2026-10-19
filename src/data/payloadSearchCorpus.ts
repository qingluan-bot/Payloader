// P1-2 搜索语料：命令文本不进首屏 public-data（gzip 预算留给列表与导航），由本模块
// 在空闲/首次搜索时延迟拉取 /api/payload-search-corpus 并并入搜索索引，保证
// "按命令内容搜 Payload"的行为不回归。语料为语言中立文本（命令标题/描述双语+命令
// 原文+前置条件），切换界面语言无需重新拉取。失败后 60s 内不重试，期间搜索回落到
// 列表字段仍可用。

export type PayloadSearchCorpus = ReadonlyMap<string, string>;

type CorpusStatus = 'idle' | 'loading' | 'ready' | 'failed';

const RETRY_DELAY_MS = 60_000;

let status: CorpusStatus = 'idle';
let lastFailureAt = 0;
let corpus: PayloadSearchCorpus = new Map();
let pending: Promise<PayloadSearchCorpus> | null = null;

export const payloadCorpusIsReady = () => status === 'ready';

export const ensurePayloadSearchCorpus = (): Promise<PayloadSearchCorpus> => {
  if (status === 'ready') return Promise.resolve(corpus);
  if (pending) return pending;
  if (status === 'failed' && Date.now() - lastFailureAt < RETRY_DELAY_MS) {
    return Promise.resolve(corpus);
  }
  status = 'loading';
  pending = (async () => {
    try {
      const response = await fetch('/api/payload-search-corpus');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json() as { version?: number; entries?: { id?: unknown; text?: unknown }[] };
      const next = new Map<string, string>();
      for (const entry of Array.isArray(data.entries) ? data.entries : []) {
        if (entry && typeof entry.id === 'string' && typeof entry.text === 'string') {
          next.set(entry.id, entry.text);
        }
      }
      corpus = next;
      status = 'ready';
      return corpus;
    } catch {
      status = 'failed';
      lastFailureAt = Date.now();
      pending = null;
      return corpus;
    }
  })();
  return pending;
};
