// 公开数据快照缓存（自 data-store.mjs 收敛）：publicDataCache 单例集中读写失效；
// 写路径经 withCacheInvalidation 包裹，新增写函数不再依赖手工调用失效。

let publicDataCache;

// payload 全量条目索引（id → sanitize 后完整条目）：public-data 快照只发列表投影后，
// 详情端点与离线快照从这里取完整条目；失效与 publicDataCache 同步（withCacheInvalidation 路径）
let payloadFullCache;

// EXP 聚合层缓存（/api/exploits 全量源专用）：public-data 快照只含精选层，
// 聚合层万级条目单独缓存，失效与 publicDataCache 同步（withCacheInvalidation 路径）
let exploitCorpusCache;

export const readPublicDataCache = () => publicDataCache;

export const writePublicDataCache = value => {
  publicDataCache = value;
  return value;
};

export const readPayloadFullCache = () => payloadFullCache;

export const writePayloadFullCache = value => {
  payloadFullCache = value;
  return value;
};

export const readExploitCorpusCache = () => exploitCorpusCache;

export const writeExploitCorpusCache = value => {
  exploitCorpusCache = value;
  return value;
};

export const invalidatePublicDataCache = () => {
  publicDataCache = undefined;
  payloadFullCache = undefined;
  exploitCorpusCache = undefined;
};

// 同步 throw 保持同步抛出（如 resetDefaultData 的参数校验）；写路径返回 promise 时，失效排在写完成之后
export const withCacheInvalidation = work => (...args) => {
  const result = work(...args);
  if (result && typeof result.then === 'function') {
    return result.then(value => {
      invalidatePublicDataCache();
      return value;
    });
  }
  invalidatePublicDataCache();
  return result;
};
